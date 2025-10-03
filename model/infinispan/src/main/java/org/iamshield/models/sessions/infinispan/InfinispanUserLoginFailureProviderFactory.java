/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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

import java.util.Set;

import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.cluster.ClusterProvider;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.UserLoginFailureProvider;
import org.iamshield.models.UserLoginFailureProviderFactory;
import org.iamshield.models.UserModel;
import org.iamshield.models.sessions.infinispan.changes.CacheHolder;
import org.iamshield.models.sessions.infinispan.changes.InfinispanChangelogBasedTransaction;
import org.iamshield.models.sessions.infinispan.changes.InfinispanChangesUtils;
import org.iamshield.models.sessions.infinispan.entities.LoginFailureEntity;
import org.iamshield.models.sessions.infinispan.entities.LoginFailureKey;
import org.iamshield.models.sessions.infinispan.events.AbstractUserSessionClusterListener;
import org.iamshield.models.sessions.infinispan.events.RealmRemovedSessionEvent;
import org.iamshield.models.sessions.infinispan.events.RemoveAllUserLoginFailuresEvent;
import org.iamshield.models.sessions.infinispan.transaction.InfinispanTransactionProvider;
import org.iamshield.models.sessions.infinispan.util.SessionTimeouts;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.models.utils.PostMigrationEvent;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderEvent;
import org.iamshield.provider.ProviderEventListener;

import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public class InfinispanUserLoginFailureProviderFactory implements UserLoginFailureProviderFactory<InfinispanUserLoginFailureProvider>, EnvironmentDependentProviderFactory, ProviderEventListener {

    private static final Logger log = Logger.getLogger(InfinispanUserLoginFailureProviderFactory.class);
    public static final String REALM_REMOVED_SESSION_EVENT = "REALM_REMOVED_EVENT_SESSIONS";
    public static final String REMOVE_ALL_LOGIN_FAILURES_EVENT = "REMOVE_ALL_LOGIN_FAILURES_EVENT";

    private CacheHolder<LoginFailureKey, LoginFailureEntity> cacheHolder;

    @Override
    public InfinispanUserLoginFailureProvider create(IAMShieldSession session) {
        return new InfinispanUserLoginFailureProvider(session, createTransaction(session));
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(final IAMShieldSessionFactory factory) {
        factory.register(this);
        try (var session = factory.create()) {
            cacheHolder = InfinispanChangesUtils.createWithCache(session, LOGIN_FAILURE_CACHE_NAME, SessionTimeouts::getLoginFailuresLifespanMs, SessionTimeouts::getLoginFailuresMaxIdleMs);
        }
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(InfinispanConnectionProvider.class, InfinispanTransactionProvider.class);
    }

    protected void registerClusterListeners(IAMShieldSession session) {
        IAMShieldSessionFactory sessionFactory = session.getIAMShieldSessionFactory();
        ClusterProvider cluster = session.getProvider(ClusterProvider.class);

        cluster.registerListener(REALM_REMOVED_SESSION_EVENT,
                new AbstractUserSessionClusterListener<RealmRemovedSessionEvent, UserLoginFailureProvider>(sessionFactory, UserLoginFailureProvider.class) {

                    @Override
                    protected void eventReceived(UserLoginFailureProvider provider, RealmRemovedSessionEvent sessionEvent) {
                        if (provider instanceof InfinispanUserLoginFailureProvider) {
                            ((InfinispanUserLoginFailureProvider) provider).removeAllLocalUserLoginFailuresEvent(sessionEvent.getRealmId());
                        }
                    }
        });

        cluster.registerListener(REMOVE_ALL_LOGIN_FAILURES_EVENT,
                new AbstractUserSessionClusterListener<RemoveAllUserLoginFailuresEvent, UserLoginFailureProvider>(sessionFactory, UserLoginFailureProvider.class) {

            @Override
            protected void eventReceived(UserLoginFailureProvider provider, RemoveAllUserLoginFailuresEvent sessionEvent) {
                if (provider instanceof InfinispanUserLoginFailureProvider) {
                    ((InfinispanUserLoginFailureProvider) provider).removeAllLocalUserLoginFailuresEvent(sessionEvent.getRealmId());
                }
            }

        });

        log.debug("Registered cluster listeners");
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
    public void onEvent(ProviderEvent event) {
        if (event instanceof PostMigrationEvent pme) {
            IAMShieldModelUtils.runJobInTransaction(pme.getFactory(), this::registerClusterListeners);
        } else if (event instanceof UserModel.UserRemovedEvent userRemovedEvent) {
            UserLoginFailureProvider provider = userRemovedEvent.getIAMShieldSession().getProvider(UserLoginFailureProvider.class, getId());
            provider.removeUserLoginFailure(userRemovedEvent.getRealm(), userRemovedEvent.getUser().getId());
        }
    }

    private InfinispanChangelogBasedTransaction<LoginFailureKey, LoginFailureEntity> createTransaction(IAMShieldSession session) {
        var tx = new InfinispanChangelogBasedTransaction<>(session, cacheHolder);
        session.getProvider(InfinispanTransactionProvider.class).registerTransaction(tx);
        return tx;
    }
}
