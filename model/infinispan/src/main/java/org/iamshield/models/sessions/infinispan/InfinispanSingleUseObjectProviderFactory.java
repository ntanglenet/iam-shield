/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.models.sessions.infinispan;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.infinispan.commons.api.BasicCache;
import org.iamshield.Config;
import org.iamshield.common.util.Time;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.SingleUseObjectProvider;
import org.iamshield.models.SingleUseObjectProviderFactory;
import org.iamshield.models.session.RevokedTokenPersisterProvider;
import org.iamshield.models.sessions.infinispan.entities.SingleUseObjectValueEntity;
import org.iamshield.models.sessions.infinispan.transaction.InfinispanTransactionProvider;
import org.iamshield.models.utils.PostMigrationEvent;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.provider.ServerInfoAwareProviderFactory;

import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.ACTION_TOKEN_CACHE;
import static org.iamshield.storage.datastore.DefaultDatastoreProviderFactory.setupClearExpiredRevokedTokensScheduledTask;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class InfinispanSingleUseObjectProviderFactory implements SingleUseObjectProviderFactory<InfinispanSingleUseObjectProvider>, EnvironmentDependentProviderFactory, ServerInfoAwareProviderFactory {

    public static final String CONFIG_PERSIST_REVOKED_TOKENS = "persistRevokedTokens";
    public static final boolean DEFAULT_PERSIST_REVOKED_TOKENS = true;
    public static final String LOADED = "loaded" + SingleUseObjectProvider.REVOKED_KEY;

    protected BasicCache<String, SingleUseObjectValueEntity> singleUseObjectCache;

    private volatile boolean initialized;
    private boolean persistRevokedTokens;

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(InfinispanConnectionProvider.class, InfinispanTransactionProvider.class);
    }

    @Override
    public InfinispanSingleUseObjectProvider create(IAMShieldSession session) {
        initialize(session);
        return new InfinispanSingleUseObjectProvider(session, singleUseObjectCache, persistRevokedTokens, createTransaction(session));
    }

    @Override
    public void init(Config.Scope config) {
        persistRevokedTokens = config.getBoolean(CONFIG_PERSIST_REVOKED_TOKENS, DEFAULT_PERSIST_REVOKED_TOKENS);
    }

    private void initialize(IAMShieldSession session) {
        if (persistRevokedTokens && !initialized) {
            synchronized (this) {
                if (!initialized) {
                    RevokedTokenPersisterProvider provider = session.getProvider(RevokedTokenPersisterProvider.class);
                    if (singleUseObjectCache.get(LOADED) == null) {
                        // in a cluster, multiple Keycloak instances might load the same data in parallel, but that wouldn't matter
                        provider.getAllRevokedTokens().forEach(revokedToken -> {
                            long lifespanSeconds = revokedToken.expiry() - Time.currentTime();
                            if (lifespanSeconds > 0) {
                                singleUseObjectCache.put(revokedToken.tokenId() + SingleUseObjectProvider.REVOKED_KEY, new SingleUseObjectValueEntity(Collections.emptyMap()),
                                         Time.toMillis(lifespanSeconds), TimeUnit.MILLISECONDS);
                            }
                        });
                        singleUseObjectCache.put(LOADED, new SingleUseObjectValueEntity(Collections.emptyMap()));
                    }
                    initialized = true;
                }
            }
        }
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        // It is necessary to put the cache initialization here, otherwise the cache would be initialized lazily, that
        // means also listeners will start only after first cache initialization - that would be too late
        if (singleUseObjectCache == null) {
            try (var session = factory.create()) {
                InfinispanConnectionProvider connections = session.getProvider(InfinispanConnectionProvider.class);
                singleUseObjectCache = connections.getCache(ACTION_TOKEN_CACHE);
            }
        }

        if (persistRevokedTokens) {
            factory.register(event -> {
                if (event instanceof PostMigrationEvent pme) {
                    IAMShieldSessionFactory sessionFactory = pme.getFactory();
                    setupClearExpiredRevokedTokensScheduledTask(sessionFactory);
                    try (IAMShieldSession session = sessionFactory.create()) {
                        // load sessions during startup, not on first request to avoid congestion
                        initialize(session);
                    }
                }
            });
        }
    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return InfinispanUtils.EMBEDDED_PROVIDER_ID;
    }

    @Override
    public int order() {
        return InfinispanUtils.PROVIDER_ORDER;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return InfinispanUtils.isEmbeddedInfinispan();
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        Map<String, String> info = new HashMap<>();
        info.put(CONFIG_PERSIST_REVOKED_TOKENS, Boolean.toString(persistRevokedTokens));
        return info;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

        builder.property()
                .name(CONFIG_PERSIST_REVOKED_TOKENS)
                .type("boolean")
                .helpText("If revoked tokens are stored persistently across restarts")
                .defaultValue(DEFAULT_PERSIST_REVOKED_TOKENS)
                .add();

        return builder.build();
    }

    private static InfinispanIAMShieldTransaction createTransaction(IAMShieldSession session) {
        InfinispanTransactionProvider transactionProvider = session.getProvider(InfinispanTransactionProvider.class);
        InfinispanIAMShieldTransaction tx = new InfinispanIAMShieldTransaction();
        transactionProvider.registerTransaction(tx);
        return tx;
    }

}

