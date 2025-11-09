/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.models.sessions.infinispan.remote;

import java.lang.invoke.MethodHandles;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.util.concurrent.BlockingManager;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.marshalling.Marshalling;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.sessions.infinispan.InfinispanAuthenticationSessionProviderFactory;
import org.iamshield.models.sessions.infinispan.changes.remote.remover.query.ByRealmIdQueryConditionalRemover;
import org.iamshield.models.sessions.infinispan.changes.remote.updater.UpdaterFactory;
import org.iamshield.models.sessions.infinispan.changes.remote.updater.authsession.RootAuthenticationSessionUpdater;
import org.iamshield.models.sessions.infinispan.entities.RootAuthenticationSessionEntity;
import org.iamshield.models.sessions.infinispan.remote.transaction.AuthenticationSessionChangeLogTransaction;
import org.iamshield.models.sessions.infinispan.remote.transaction.RemoteChangeLogTransaction;
import org.iamshield.models.sessions.infinispan.transaction.InfinispanTransactionProvider;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.provider.ServerInfoAwareProviderFactory;
import org.iamshield.sessions.AuthenticationSessionProviderFactory;

import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.AUTHENTICATION_SESSIONS_CACHE_NAME;
import static org.iamshield.models.sessions.infinispan.InfinispanAuthenticationSessionProviderFactory.DEFAULT_AUTH_SESSIONS_LIMIT;

public class RemoteInfinispanAuthenticationSessionProviderFactory implements AuthenticationSessionProviderFactory<RemoteInfinispanAuthenticationSessionProvider>, UpdaterFactory<String, RootAuthenticationSessionEntity, RootAuthenticationSessionUpdater>, EnvironmentDependentProviderFactory, RemoteChangeLogTransaction.SharedState<String, RootAuthenticationSessionEntity>, ServerInfoAwareProviderFactory {

    private final static Logger logger = Logger.getLogger(MethodHandles.lookup().lookupClass());
    public static final String PROTO_ENTITY = Marshalling.protoEntity(RootAuthenticationSessionEntity.class);

    private int authSessionsLimit;
    private volatile RemoteCache<String, RootAuthenticationSessionEntity> cache;

    private volatile BlockingManager blockingManager;
    private volatile int maxRetries = InfinispanUtils.DEFAULT_MAX_RETRIES;
    private volatile int backOffBaseTimeMillis = InfinispanUtils.DEFAULT_RETRIES_BASE_TIME_MILLIS;

    @Override
    public boolean isSupported(Config.Scope config) {
        return InfinispanUtils.isRemoteInfinispan();
    }

    @Override
    public RemoteInfinispanAuthenticationSessionProvider create(IAMShieldSession session) {
        return new RemoteInfinispanAuthenticationSessionProvider(session, authSessionsLimit, createAndEnlistTransaction(session));
    }

    @Override
    public void init(Config.Scope config) {
        authSessionsLimit = InfinispanAuthenticationSessionProviderFactory.getAuthSessionsLimit(config);
        maxRetries = InfinispanUtils.getMaxRetries(config);
        backOffBaseTimeMillis = InfinispanUtils.getRetryBaseTimeMillis(config);
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        try (var session = factory.create()) {
            var provider = session.getProvider(InfinispanConnectionProvider.class);
            cache = provider.getRemoteCache(AUTHENTICATION_SESSIONS_CACHE_NAME);
            blockingManager = provider.getBlockingManager();
            logger.debugf("Provided initialized. session limit=%s", authSessionsLimit);
        }
    }

    @Override
    public void close() {
        cache = null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {

        ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
        InfinispanUtils.configureMaxRetries(builder);
        InfinispanUtils.configureRetryBaseTime(builder);
        return builder.property()
                .name("authSessionsLimit")
                .type("int")
                .helpText("The maximum number of concurrent authentication sessions per RootAuthenticationSession.")
                .defaultValue(DEFAULT_AUTH_SESSIONS_LIMIT)
                .add()
                .build();
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        Map<String, String> map = new HashMap<>();
        InfinispanUtils.maxRetriesToOperationalInfo(map, maxRetries);
        InfinispanUtils.retryBaseTimeMillisToOperationalInfo(map, backOffBaseTimeMillis);
        return map;
    }

    @Override
    public RootAuthenticationSessionUpdater create(String key, RootAuthenticationSessionEntity entity) {
        return  RootAuthenticationSessionUpdater.create(key, entity);
    }

    @Override
    public RootAuthenticationSessionUpdater wrapFromCache(String key, RootAuthenticationSessionEntity value, long version) {
        return RootAuthenticationSessionUpdater.wrap(key, value, version);
    }

    @Override
    public RootAuthenticationSessionUpdater deleted(String key) {
        return RootAuthenticationSessionUpdater.delete(key);
    }

    @Override
    public RemoteCache<String, RootAuthenticationSessionEntity> cache() {
        return cache;
    }

    @Override
    public String getId() {
        return InfinispanUtils.REMOTE_PROVIDER_ID;
    }

    @Override
    public int order() {
        return InfinispanUtils.PROVIDER_ORDER;
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(InfinispanTransactionProvider.class);
    }

    private AuthenticationSessionChangeLogTransaction createAndEnlistTransaction(IAMShieldSession session) {
        var provider = session.getProvider(InfinispanTransactionProvider.class);
        var tx = new AuthenticationSessionChangeLogTransaction(this, this, new ByRealmIdQueryConditionalRemover<>(PROTO_ENTITY));
        provider.registerTransaction(tx);
        return tx;
    }

    @Override
    public int maxRetries() {
        return maxRetries;
    }

    @Override
    public int backOffBaseTimeMillis() {
        return backOffBaseTimeMillis;
    }

    @Override
    public BlockingManager blockingManager() {
        return blockingManager;
    }
}
