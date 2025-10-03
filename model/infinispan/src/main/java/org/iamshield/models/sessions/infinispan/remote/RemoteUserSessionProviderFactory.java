package org.iamshield.models.sessions.infinispan.remote;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.util.concurrent.BlockingManager;
import org.iamshield.Config;
import org.iamshield.common.util.MultiSiteUtils;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserSessionProvider;
import org.iamshield.models.UserSessionProviderFactory;
import org.iamshield.models.session.UserSessionPersisterProvider;
import org.iamshield.models.sessions.infinispan.changes.remote.updater.client.AuthenticatedClientSessionUpdater;
import org.iamshield.models.sessions.infinispan.changes.remote.updater.user.UserSessionUpdater;
import org.iamshield.models.sessions.infinispan.entities.ClientSessionKey;
import org.iamshield.models.sessions.infinispan.entities.RemoteAuthenticatedClientSessionEntity;
import org.iamshield.models.sessions.infinispan.entities.RemoteUserSessionEntity;
import org.iamshield.models.sessions.infinispan.remote.transaction.ClientSessionChangeLogTransaction;
import org.iamshield.models.sessions.infinispan.remote.transaction.RemoteChangeLogTransaction;
import org.iamshield.models.sessions.infinispan.remote.transaction.UserSessionChangeLogTransaction;
import org.iamshield.models.sessions.infinispan.remote.transaction.UserSessionTransaction;
import org.iamshield.models.sessions.infinispan.transaction.InfinispanTransactionProvider;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.provider.ProviderEvent;
import org.iamshield.provider.ProviderEventListener;
import org.iamshield.provider.ServerInfoAwareProviderFactory;

import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME;
import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME;
import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME;
import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.USER_SESSION_CACHE_NAME;

public class RemoteUserSessionProviderFactory implements UserSessionProviderFactory<RemoteUserSessionProvider>, EnvironmentDependentProviderFactory, ProviderEventListener, ServerInfoAwareProviderFactory {

    // Sessions are close to 1KB of data. Fetch 1MB per batch request (can be configured)
    private static final int DEFAULT_BATCH_SIZE = 1024;
    private static final String CONFIG_MAX_BATCH_SIZE = "batchSize";

    private volatile SharedStateImpl<String, RemoteUserSessionEntity> userSessionState;
    private volatile SharedStateImpl<String, RemoteUserSessionEntity> offlineUserSessionState;
    private volatile SharedStateImpl<ClientSessionKey, RemoteAuthenticatedClientSessionEntity> clientSessionState;
    private volatile SharedStateImpl<ClientSessionKey, RemoteAuthenticatedClientSessionEntity> offlineClientSessionState;
    private volatile BlockingManager blockingManager;
    private volatile int batchSize = DEFAULT_BATCH_SIZE;
    private volatile int maxRetries = InfinispanUtils.DEFAULT_MAX_RETRIES;
    private volatile int backOffBaseTimeMillis = InfinispanUtils.DEFAULT_RETRIES_BASE_TIME_MILLIS;

    @Override
    public RemoteUserSessionProvider create(IAMShieldSession session) {
        var provider = session.getProvider(InfinispanTransactionProvider.class);
        var tx = createTransaction(session);
        provider.registerTransaction(tx);
        return new RemoteUserSessionProvider(session, tx, batchSize);
    }

    @Override
    public void init(Config.Scope config) {
        batchSize = Math.max(1, config.getInt(CONFIG_MAX_BATCH_SIZE, DEFAULT_BATCH_SIZE));
        maxRetries = InfinispanUtils.getMaxRetries(config);
        backOffBaseTimeMillis = InfinispanUtils.getRetryBaseTimeMillis(config);
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        try (var session = factory.create()) {
            lazyInit(session);
        }
        factory.register(this);
    }

    @Override
    public void close() {
        blockingManager = null;
        userSessionState = null;
        offlineUserSessionState = null;
        clientSessionState = null;
        offlineClientSessionState = null;
    }

    @Override
    public String getId() {
        return InfinispanUtils.REMOTE_PROVIDER_ID;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return InfinispanUtils.isRemoteInfinispan() && !MultiSiteUtils.isPersistentSessionsEnabled();
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
        builder.property()
                .name(CONFIG_MAX_BATCH_SIZE)
                .type("int")
                .helpText("Batch size when streaming session from the remote cache")
                .defaultValue(DEFAULT_BATCH_SIZE)
                .add();

        InfinispanUtils.configureMaxRetries(builder);
        InfinispanUtils.configureRetryBaseTime(builder);

        return builder.build();
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        Map<String, String> map = new HashMap<>();
        map.put(CONFIG_MAX_BATCH_SIZE, Integer.toString(batchSize));
        InfinispanUtils.maxRetriesToOperationalInfo(map, maxRetries);
        InfinispanUtils.retryBaseTimeMillisToOperationalInfo(map, backOffBaseTimeMillis);
        return map;
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof UserModel.UserRemovedEvent ure) {
            onUserRemoved(ure);
        }
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(InfinispanTransactionProvider.class);
    }

    private void onUserRemoved(UserModel.UserRemovedEvent event) {
        event.getIAMShieldSession().getProvider(UserSessionProvider.class, getId()).removeUserSessions(event.getRealm(), event.getUser());
        event.getIAMShieldSession().getProvider(UserSessionPersisterProvider.class).onUserRemoved(event.getRealm(), event.getUser());
    }

    private void lazyInit(IAMShieldSession session) {
        if (blockingManager != null) {
            return;
        }
        var connections = session.getProvider(InfinispanConnectionProvider.class);
        userSessionState = new SharedStateImpl<>(connections.getRemoteCache(USER_SESSION_CACHE_NAME));
        offlineUserSessionState = new SharedStateImpl<>(connections.getRemoteCache(OFFLINE_USER_SESSION_CACHE_NAME));
        clientSessionState = new SharedStateImpl<>(connections.getRemoteCache(CLIENT_SESSION_CACHE_NAME));
        offlineClientSessionState = new SharedStateImpl<>(connections.getRemoteCache(OFFLINE_CLIENT_SESSION_CACHE_NAME));
        blockingManager = connections.getBlockingManager();
    }

    private UserSessionTransaction createTransaction(IAMShieldSession session) {
        lazyInit(session);
        return new UserSessionTransaction(
                new UserSessionChangeLogTransaction(UserSessionUpdater.onlineFactory(), userSessionState),
                new UserSessionChangeLogTransaction(UserSessionUpdater.offlineFactory(), offlineUserSessionState),
                new ClientSessionChangeLogTransaction(AuthenticatedClientSessionUpdater.onlineFactory(), clientSessionState),
                new ClientSessionChangeLogTransaction(AuthenticatedClientSessionUpdater.offlineFactory(), offlineClientSessionState)
        );
    }

    private class SharedStateImpl<K, V> implements RemoteChangeLogTransaction.SharedState<K, V> {

        private final RemoteCache<K, V> cache;

        private SharedStateImpl(RemoteCache<K, V> cache) {
            this.cache = cache;
        }

        @Override
        public RemoteCache<K, V> cache() {
            return cache;
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
}
