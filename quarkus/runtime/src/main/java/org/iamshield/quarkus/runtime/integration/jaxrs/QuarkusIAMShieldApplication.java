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

package org.iamshield.quarkus.runtime.integration.jaxrs;

import org.iamshield.config.BootstrapAdminOptions;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.platform.Platform;
import org.iamshield.quarkus.runtime.configuration.Configuration;
import org.iamshield.quarkus.runtime.configuration.MicroProfileConfigProvider;
import org.iamshield.quarkus.runtime.configuration.PropertyMappingInterceptor;
import org.iamshield.quarkus.runtime.integration.QuarkusIAMShieldSessionFactory;
import org.iamshield.quarkus.runtime.integration.QuarkusPlatform;
import org.iamshield.services.ServicesLogger;
import org.iamshield.services.managers.ApplianceBootstrap;
import org.iamshield.services.resources.IAMShieldApplication;
import org.iamshield.utils.StringUtil;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.common.annotation.Blocking;
import jakarta.enterprise.event.Observes;
import jakarta.ws.rs.ApplicationPath;

@ApplicationPath("/")
@Blocking
public class QuarkusIAMShieldApplication extends IAMShieldApplication {

    private static final String IAMSHIELD_ADMIN_ENV_VAR = "IAMSHIELD_ADMIN";
    private static final String IAMSHIELD_ADMIN_PASSWORD_ENV_VAR = "IAMSHIELD_ADMIN_PASSWORD";

    void onStartupEvent(@Observes StartupEvent event) {
        // Initialize platform now that we're at runtime
        initializePlatform();

        QuarkusPlatform platform = (QuarkusPlatform) Platform.getPlatform();
        platform.started();
        startup();
    }

    void onShutdownEvent(@Observes ShutdownEvent event) {
        shutdown();
    }

    @Override
    public IAMShieldSessionFactory createSessionFactory() {
        QuarkusIAMShieldSessionFactory instance = QuarkusIAMShieldSessionFactory.getInstance();
        instance.init();
        return instance;
    }

    @Override
    protected void loadConfig() {
        // no need to load config provider because we force quarkus impl
    }

    @Override
    protected void createTemporaryAdmin(IAMShieldSession session) {
        var adminUsername = getOption(BootstrapAdminOptions.USERNAME.getKey(), IAMSHIELD_ADMIN_ENV_VAR);
        var adminPassword = getOption(BootstrapAdminOptions.PASSWORD.getKey(), IAMSHIELD_ADMIN_PASSWORD_ENV_VAR);

        var clientId = Configuration.getOptionalKcValue(BootstrapAdminOptions.CLIENT_ID.getKey()).orElse(null);
        var clientSecret = Configuration.getOptionalKcValue(BootstrapAdminOptions.CLIENT_SECRET.getKey()).orElse(null);

        try {
            //Integer expiration = Configuration.getOptionalKcValue(BootstrapAdminOptions.EXPIRATION.getKey()).map(Integer::valueOf).orElse(null);
            if (StringUtil.isNotBlank(adminPassword) && !createTemporaryMasterRealmAdminUser(adminUsername, adminPassword, /*expiration,*/ session)) {
                throw new RuntimeException("Aborting startup and the creation of the master realm, because the temporary admin user account could not be created.");
            }
            if (StringUtil.isNotBlank(clientSecret) && !createTemporaryMasterRealmAdminService(clientId, clientSecret, /*expiration,*/ session)) {
                throw new RuntimeException("Aborting startup and the creation of the master realm, because the temporary admin service account could not be created.");
            }
        } catch (NumberFormatException e) {
            throw new RuntimeException("Invalid admin expiration value provided. An integer is expected.", e);
        }
    }

    private String getOption(String option, String envVar) {
        PropertyMappingInterceptor.disable(); // disable default handling
        try {
            return Configuration.getOptionalKcValue(option).orElseGet(() -> {
                String value = System.getenv(envVar);
                if (value != null) {
                    ServicesLogger.LOGGER.usingDeprecatedEnvironmentVariable(envVar, Configuration.toEnvVarFormat(MicroProfileConfigProvider.NS_IAMSHIELD_PREFIX + option));
                }
                return value;
            });
        } finally {
            PropertyMappingInterceptor.enable();
        }
    }

    public boolean createTemporaryMasterRealmAdminUser(String adminUserName, String adminPassword, /*Integer adminExpiration,*/ IAMShieldSession session) {
        return new ApplianceBootstrap(session).createMasterRealmAdminUser(adminUserName, adminPassword, true /*, adminExpiration*/, false);
    }

    public boolean createTemporaryMasterRealmAdminService(String clientId, String clientSecret, /*Integer adminExpiration,*/ IAMShieldSession session) {
        return new ApplianceBootstrap(session).createTemporaryMasterRealmAdminService(clientId, clientSecret /*, adminExpiration*/);
    }

}
