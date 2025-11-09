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
package org.iamshield.services.resources;

import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.common.crypto.CryptoIntegration;
import org.iamshield.config.ConfigProviderFactory;
import org.iamshield.exportimport.ExportImportConfig;
import org.iamshield.exportimport.ExportImportManager;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.IAMShieldSessionTask;
import org.iamshield.models.dblock.DBLockManager;
import org.iamshield.models.dblock.DBLockProvider;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.models.utils.PostMigrationEvent;
import org.iamshield.platform.Platform;
import org.iamshield.platform.PlatformProvider;
import org.iamshield.services.managers.ApplianceBootstrap;
import org.iamshield.transaction.JtaTransactionManagerLookup;

import java.util.NoSuchElementException;
import java.util.ServiceLoader;

import jakarta.transaction.SystemException;
import jakarta.transaction.Transaction;
import jakarta.ws.rs.core.Application;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 *
 */
public abstract class IAMShieldApplication extends Application {

    private static final Logger logger = Logger.getLogger(IAMShieldApplication.class);

    private PlatformProvider platform;

    protected PlatformProvider getPlatform() {
        if (platform == null) {
            platform = Platform.getPlatform();
        }
        return platform;
    }

    private static IAMShieldSessionFactory sessionFactory;

    public IAMShieldApplication() {
        // Defer platform initialization to avoid issues during build-time scanning
    }

    protected void initializePlatform() {
        try {
            logger.debugv("PlatformProvider: {0}", getPlatform().getClass().getName());
            loadConfig();

            getPlatform().onStartup(this::startup);
            getPlatform().onShutdown(this::shutdown);

        } catch (Throwable t) {
            getPlatform().exit(t);
        }
    }

    protected void startup() {
        Profile.getInstance().logUnsupportedFeatures();
        CryptoIntegration.init(IAMShieldApplication.class.getClassLoader());
        IAMShieldApplication.sessionFactory = createSessionFactory();

        ExportImportManager[] exportImportManager = new ExportImportManager[1];

        IAMShieldModelUtils.runJobInTransaction(sessionFactory, new IAMShieldSessionTask() {
            @Override
            public void run(IAMShieldSession session) {
                DBLockManager dbLockManager = new DBLockManager(session);
                dbLockManager.checkForcedUnlock();
                DBLockProvider dbLock = dbLockManager.getDBLock();
                dbLock.waitForLock(DBLockProvider.Namespace.KEYCLOAK_BOOT);
                try {
                    exportImportManager[0] = bootstrap();
                } finally {
                    dbLock.releaseLock();
                }
            }
        });

        if (exportImportManager[0].isRunExport()) {
            exportImportManager[0].runExport();
        }

        sessionFactory.publish(new PostMigrationEvent(sessionFactory));
    }

    protected void shutdown() {
        if (sessionFactory != null) {
            sessionFactory.close();
        }
    }

    private static class BootstrapState {
        ExportImportManager exportImportManager;
        boolean newInstall;
    }

    // Bootstrap master realm, import realms and create admin user.
    protected ExportImportManager bootstrap() {
        BootstrapState bootstrapState = new BootstrapState();

        logger.debug("bootstrap");
        IAMShieldModelUtils.runJobInTransaction(sessionFactory, new IAMShieldSessionTask() {
            @Override
            public void run(IAMShieldSession session) {
                // TODO what is the purpose of following piece of code? Leaving it as is for now.
                JtaTransactionManagerLookup lookup = (JtaTransactionManagerLookup) sessionFactory.getProviderFactory(JtaTransactionManagerLookup.class);
                if (lookup != null) {
                    if (lookup.getTransactionManager() != null) {
                        try {
                            Transaction transaction = lookup.getTransactionManager().getTransaction();
                            logger.debugv("bootstrap current transaction? {0}", transaction != null);
                            if (transaction != null) {
                                logger.debugv("bootstrap current transaction status? {0}", transaction.getStatus());
                            }
                        } catch (SystemException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
                // TODO up here ^^

                ApplianceBootstrap applianceBootstrap = new ApplianceBootstrap(session);
                var exportImportManager = bootstrapState.exportImportManager = new ExportImportManager(session);
                bootstrapState.newInstall = applianceBootstrap.isNewInstall();
                if (bootstrapState.newInstall) {
                    boolean existing = ExportImportConfig.isSingleTransaction();
                    ExportImportConfig.setSingleTransaction(true);
                    try {
                        if (!exportImportManager.isImportMasterIncluded()) {
                            applianceBootstrap.createMasterRealm();
                        }
                        // these are also running in the initial bootstrap transaction - if there is a problem, the server won't be initialized at all
                        exportImportManager.runImport();
                        createTemporaryAdmin(session);
                    } finally {
                        ExportImportConfig.setSingleTransaction(existing);
                    }
                }
            }
        });

        if (!bootstrapState.newInstall) {
            bootstrapState.exportImportManager.runImport();
        }

        return bootstrapState.exportImportManager;
    }

    protected abstract void createTemporaryAdmin(IAMShieldSession session);

    protected void loadConfig() {

        ServiceLoader<ConfigProviderFactory> loader = ServiceLoader.load(ConfigProviderFactory.class, IAMShieldApplication.class.getClassLoader());

        try {
            ConfigProviderFactory factory = loader.iterator().next();
            logger.debugv("ConfigProvider: {0}", factory.getClass().getName());
            Config.init(factory.create().orElseThrow(() -> new RuntimeException("Failed to load Keycloak configuration")));
        } catch (NoSuchElementException e) {
            throw new RuntimeException("No valid ConfigProvider found");
        }

    }

    protected abstract IAMShieldSessionFactory createSessionFactory();

    public static IAMShieldSessionFactory getSessionFactory() {
        return sessionFactory;
    }

}
