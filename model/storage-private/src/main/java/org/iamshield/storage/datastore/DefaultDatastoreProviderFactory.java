/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.storage.datastore;

import java.util.Arrays;
import java.util.List;

import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.Config.Scope;
import org.iamshield.migration.MigrationModelManager;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.utils.PostMigrationEvent;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.provider.ProviderEvent;
import org.iamshield.provider.ProviderEventListener;
import org.iamshield.services.scheduled.ClearExpiredAdminEvents;
import org.iamshield.services.scheduled.ClearExpiredClientInitialAccessTokens;
import org.iamshield.services.scheduled.ClearExpiredEvents;
import org.iamshield.services.scheduled.ClearExpiredRevokedTokens;
import org.iamshield.services.scheduled.ClearExpiredUserSessions;
import org.iamshield.services.scheduled.ClusterAwareScheduledTaskRunner;
import org.iamshield.storage.DatastoreProvider;
import org.iamshield.storage.DatastoreProviderFactory;
import org.iamshield.storage.StoreMigrateRepresentationEvent;
import org.iamshield.storage.StoreSyncEvent;
import org.iamshield.storage.managers.UserStorageSyncManager;
import org.iamshield.timer.ScheduledTask;
import org.iamshield.timer.TimerProvider;

public class DefaultDatastoreProviderFactory implements DatastoreProviderFactory, ProviderEventListener {

    private static final String PROVIDER_ID = "legacy";

    public static final String ALLOW_MIGRATE_EXISTING_DB_TO_SNAPSHOT_OPTION = "allowMigrateExistingDatabaseToSnapshot";

    private static final Logger logger = Logger.getLogger(DefaultDatastoreProviderFactory.class);

    private long clientStorageProviderTimeout;
    private long roleStorageProviderTimeout;
    private boolean allowMigrateExistingDatabaseToSnapshot;
    private Runnable onClose;

    @Override
    public DatastoreProvider create(IAMShieldSession session) {
        return new DefaultDatastoreProvider(this, session);
    }

    @Override
    public void init(Scope config) {
        clientStorageProviderTimeout = Config.scope("client").getLong("storageProviderTimeout", 3000L);
        roleStorageProviderTimeout = Config.scope("role").getLong("storageProviderTimeout", 3000L);
        allowMigrateExistingDatabaseToSnapshot = config.getBoolean(ALLOW_MIGRATE_EXISTING_DB_TO_SNAPSHOT_OPTION, false);
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        factory.register(this);
        onClose = () -> factory.unregister(this);
    }

    @Override
    public void close() {
        if (onClose != null) {
            onClose.run();
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(ALLOW_MIGRATE_EXISTING_DB_TO_SNAPSHOT_OPTION)
                .type("boolean")
                .helpText("By default, it is not allowed to run the snapshot/development server against the database, which was previously migrated to some officially released server version. As an attempt of doing this " +
                        "indicates that you are trying to run development server against production database, which can result in a loss or corruption of data, and also does not allow upgrading. If it is really intended, you can use this option, which will allow to use " +
                        "nightly/development server against production database when explicitly switch to true. This option is recommended just in the development environments and should be never used in the production!")
                .defaultValue(false)
                .add()
                .build();
    }

    public long getClientStorageProviderTimeout() {
        return clientStorageProviderTimeout;
    }

    public long getRoleStorageProviderTimeout() {
        return roleStorageProviderTimeout;
    }

    boolean isAllowMigrateExistingDatabaseToSnapshot() {
        return allowMigrateExistingDatabaseToSnapshot;
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof PostMigrationEvent) {
            setupScheduledTasks(((PostMigrationEvent) event).getFactory());
        } else if (event instanceof StoreSyncEvent) {
            StoreSyncEvent ev = (StoreSyncEvent) event;
            UserStorageSyncManager.notifyToRefreshPeriodicSyncAll(ev.getSession(), ev.getRealm(), ev.getRemoved());
        } else if (event instanceof StoreMigrateRepresentationEvent) {
            StoreMigrateRepresentationEvent ev = (StoreMigrateRepresentationEvent) event;
            MigrationModelManager.migrateImport(ev.getSession(), ev.getRealm(), ev.getRep(), ev.isSkipUserDependent());
        }
    }

    public static void setupScheduledTasks(final IAMShieldSessionFactory sessionFactory) {
        try (IAMShieldSession session = sessionFactory.create()) {
            TimerProvider timer = session.getProvider(TimerProvider.class);
            if (timer != null) {
                scheduleTasks(sessionFactory, timer, getScheduledInterval());
            }
        }
    }

    protected static void scheduleTasks(IAMShieldSessionFactory sessionFactory, TimerProvider timer, long interval) {
        for (ScheduledTask task : getScheduledTasks()) {
            scheduleTask(timer, sessionFactory, task, interval);
        }

        UserStorageSyncManager.bootstrapPeriodic(sessionFactory, timer);
    }

    protected static List<ScheduledTask> getScheduledTasks() {
        return Arrays.asList(new ClearExpiredEvents(), new ClearExpiredAdminEvents(), new ClearExpiredClientInitialAccessTokens(), new ClearExpiredUserSessions());
    }

    protected static void scheduleTask(TimerProvider timer, IAMShieldSessionFactory sessionFactory, ScheduledTask task, long interval) {
        timer.schedule(new ClusterAwareScheduledTaskRunner(sessionFactory, task, interval), interval);
        logger.debugf("Scheduled cluster task %s with interval %s ms", task.getTaskName(), interval);
    }

    public static void setupClearExpiredRevokedTokensScheduledTask(IAMShieldSessionFactory sessionFactory) {
        try (IAMShieldSession session = sessionFactory.create()) {
            TimerProvider timer = session.getProvider(TimerProvider.class);
            if (timer != null) {
                scheduleTask(timer, sessionFactory, new ClearExpiredRevokedTokens(), getScheduledInterval());
            }
        }
    }

    public static long getScheduledInterval() {
        return Config.scope("scheduled").getLong("interval", 900L) * 1000;
    }

}
