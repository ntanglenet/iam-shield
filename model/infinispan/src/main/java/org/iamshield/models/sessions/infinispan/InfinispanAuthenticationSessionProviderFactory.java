/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.cluster.ClusterEvent;
import org.iamshield.cluster.ClusterProvider;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.cache.infinispan.events.AuthenticationSessionAuthNoteUpdateEvent;
import org.iamshield.models.sessions.infinispan.changes.CacheHolder;
import org.iamshield.models.sessions.infinispan.changes.InfinispanChangelogBasedTransaction;
import org.iamshield.models.sessions.infinispan.changes.InfinispanChangesUtils;
import org.iamshield.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.iamshield.models.sessions.infinispan.entities.AuthenticationSessionEntity;
import org.iamshield.models.sessions.infinispan.entities.RootAuthenticationSessionEntity;
import org.iamshield.models.sessions.infinispan.events.AbstractAuthSessionClusterListener;
import org.iamshield.models.sessions.infinispan.events.RealmRemovedSessionEvent;
import org.iamshield.models.sessions.infinispan.transaction.InfinispanTransactionProvider;
import org.iamshield.models.sessions.infinispan.util.InfinispanKeyGenerator;
import org.iamshield.models.sessions.infinispan.util.SessionTimeouts;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.models.utils.PostMigrationEvent;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.provider.ProviderEvent;
import org.iamshield.provider.ProviderEventListener;
import org.iamshield.sessions.AuthenticationSessionProviderFactory;

import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.AUTHENTICATION_SESSIONS_CACHE_NAME;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class InfinispanAuthenticationSessionProviderFactory implements AuthenticationSessionProviderFactory<InfinispanAuthenticationSessionProvider>, EnvironmentDependentProviderFactory, ProviderEventListener {

    private static final Logger log = Logger.getLogger(InfinispanAuthenticationSessionProviderFactory.class);

    private final InfinispanKeyGenerator keyGenerator = new InfinispanKeyGenerator();
    private CacheHolder<String, RootAuthenticationSessionEntity> cacheHolder;

    private int authSessionsLimit;

    public static final String AUTH_SESSIONS_LIMIT = "authSessionsLimit";

    public static final int DEFAULT_AUTH_SESSIONS_LIMIT = 300;

    public static final String AUTHENTICATION_SESSION_EVENTS = "AUTHENTICATION_SESSION_EVENTS";

    public static final String REALM_REMOVED_AUTHSESSION_EVENT = "REALM_REMOVED_EVENT_AUTHSESSIONS";

    @Override
    public void init(Config.Scope config) {
        authSessionsLimit = getAuthSessionsLimit(config);
    }

    public static int getAuthSessionsLimit(Config.Scope config) {
        var limit = config.getInt(AUTH_SESSIONS_LIMIT, DEFAULT_AUTH_SESSIONS_LIMIT);
        // use default if provided value is not a positive number
        return limit <= 0 ? DEFAULT_AUTH_SESSIONS_LIMIT : limit;
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        factory.register(this);
        try (var session = factory.create()) {
            cacheHolder = InfinispanChangesUtils.createWithCache(session, AUTHENTICATION_SESSIONS_CACHE_NAME, SessionTimeouts::getAuthSessionLifespanMS, SessionTimeouts::getAuthSessionMaxIdleMS);
        }
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("authSessionsLimit")
                .type("int")
                .helpText("The maximum number of concurrent authentication sessions per RootAuthenticationSession.")
                .defaultValue(DEFAULT_AUTH_SESSIONS_LIMIT)
                .add()
                .build();
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof PostMigrationEvent pme) {
            IAMShieldModelUtils.runJobInTransaction(pme.getFactory(), this::registerClusterListeners);
        }
    }

    protected void registerClusterListeners(IAMShieldSession session) {
        IAMShieldSessionFactory sessionFactory = session.getIAMShieldSessionFactory();
        ClusterProvider cluster = session.getProvider(ClusterProvider.class);

        cluster.registerListener(REALM_REMOVED_AUTHSESSION_EVENT, new AbstractAuthSessionClusterListener<RealmRemovedSessionEvent>(sessionFactory) {

            @Override
            protected void eventReceived(InfinispanAuthenticationSessionProvider provider, RealmRemovedSessionEvent sessionEvent) {
                provider.onRealmRemovedEvent(sessionEvent.getRealmId());
            }

        });
        cluster.registerListener(AUTHENTICATION_SESSION_EVENTS, this::updateAuthNotes);

        log.debug("Registered cluster listeners");
    }

    @Override
    public InfinispanAuthenticationSessionProvider create(IAMShieldSession session) {
        return new InfinispanAuthenticationSessionProvider(session, keyGenerator, createTransaction(session), authSessionsLimit);
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(InfinispanConnectionProvider.class, InfinispanTransactionProvider.class);
    }

    private void updateAuthNotes(ClusterEvent clEvent) {
        if (! (clEvent instanceof AuthenticationSessionAuthNoteUpdateEvent event)) {
            return;
        }

        var distribution = cacheHolder.cache().getAdvancedCache().getDistributionManager();
        if (distribution != null && !distribution.getCacheTopology().getDistribution(event.getAuthSessionId()).isPrimary()) {
            // Distribution is null for non-clustered caches (local-cache, used by start-dev mode).
            // If not the primary owner of the key, skip event handling.
            return;
        }

        SessionEntityWrapper<RootAuthenticationSessionEntity> authSession = cacheHolder.cache().get(event.getAuthSessionId());
        updateAuthSession(authSession, event.getTabId(), event.getAuthNotesFragment());
    }

    private void updateAuthSession(SessionEntityWrapper<RootAuthenticationSessionEntity> rootAuthSessionWrapper, String tabId, Map<String, String> authNotesFragment) {
        if (rootAuthSessionWrapper == null || rootAuthSessionWrapper.getEntity() == null) {
            return;
        }

        RootAuthenticationSessionEntity rootAuthSession = rootAuthSessionWrapper.getEntity();
        AuthenticationSessionEntity authSession = rootAuthSession.getAuthenticationSessions().get(tabId);

        if (authSession != null) {
            if (authSession.getAuthNotes() == null) {
                authSession.setAuthNotes(new ConcurrentHashMap<>());
            }

            for (Entry<String, String> me : authNotesFragment.entrySet()) {
                String value = me.getValue();
                if (value == null) {
                    authSession.getAuthNotes().remove(me.getKey());
                } else {
                    authSession.getAuthNotes().put(me.getKey(), value);
                }
            }
        }

        cacheHolder.cache().replace(rootAuthSession.getId(), new SessionEntityWrapper<>(rootAuthSessionWrapper.getLocalMetadata(), rootAuthSession));
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

    private InfinispanChangelogBasedTransaction<String, RootAuthenticationSessionEntity> createTransaction(IAMShieldSession session) {
        var tx = new InfinispanChangelogBasedTransaction<>(session, cacheHolder);
        session.getProvider(InfinispanTransactionProvider.class).registerTransaction(tx);
        return tx;
    }
}
