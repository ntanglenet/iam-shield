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

package org.iamshield.quarkus.runtime;

import java.io.File;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.hibernate.cfg.AvailableSettings;
import org.infinispan.protostream.SerializationContextInitializer;
import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.common.crypto.CryptoIntegration;
import org.iamshield.common.crypto.CryptoProvider;
import org.iamshield.common.crypto.FipsMode;
import org.iamshield.config.DatabaseOptions;
import org.iamshield.config.TruststoreOptions;
import org.iamshield.marshalling.Marshalling;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;
import org.iamshield.quarkus.runtime.configuration.Configuration;
import org.iamshield.quarkus.runtime.configuration.MicroProfileConfigProvider;
import org.iamshield.quarkus.runtime.integration.QuarkusIAMShieldSessionFactory;
import org.iamshield.quarkus.runtime.storage.database.liquibase.FastServiceLocator;
import org.iamshield.representations.userprofile.config.UPConfig;
import org.iamshield.theme.ClasspathThemeProviderFactory;
import org.iamshield.truststore.TruststoreBuilder;
import org.iamshield.userprofile.DeclarativeUserProfileProviderFactory;

import io.agroal.api.AgroalDataSource;
import io.quarkus.agroal.DataSource;
import io.quarkus.arc.Arc;
import io.quarkus.arc.InstanceHandle;
import io.quarkus.hibernate.orm.runtime.integration.HibernateOrmIntegrationRuntimeInitListener;
import io.quarkus.runtime.annotations.Recorder;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import liquibase.Scope;
import liquibase.servicelocator.ServiceLocator;

@Recorder
public class IAMShieldRecorder {

    public void initConfig() {
        Config.init(new MicroProfileConfigProvider());
    }

    public void configureProfile(Profile.ProfileName profileName, Map<Profile.Feature, Boolean> features) {
        Profile.init(profileName, features);
    }

    // default handler for redirecting to specific path
    public Handler<RoutingContext> getRedirectHandler(String redirectPath) {
        return routingContext -> routingContext.redirect(redirectPath);
    }

    // default handler for the management interface
    public Handler<RoutingContext> getManagementHandler() {
        return routingContext -> routingContext.response().end("Keycloak Management Interface");
    }

    public void configureTruststore() {
        String[] truststores = Configuration.getOptionalKcValue(TruststoreOptions.TRUSTSTORE_PATHS.getKey())
                .map(s -> s.split(",")).orElse(new String[0]);

        String dataDir = Environment.getDataDir();

        File truststoresDir = Optional.ofNullable(Environment.getHomePath()).map(path -> path.resolve("conf").resolve("truststores").toFile()).orElse(null);

        if (truststoresDir != null && truststoresDir.exists() && Optional.ofNullable(truststoresDir.list()).map(a -> a.length).orElse(0) > 0) {
            truststores = Stream.concat(Stream.of(truststoresDir.getAbsolutePath()), Stream.of(truststores)).toArray(String[]::new);
        } else if (truststores.length == 0) {
            return; // nothing to configure, we'll just use the system default
        }

        TruststoreBuilder.setSystemTruststore(truststores, true, dataDir);
    }

    public void configureLiquibase(Map<String, List<String>> services) {
        ServiceLocator locator = Scope.getCurrentScope().getServiceLocator();
        if (locator instanceof FastServiceLocator) {
            ((FastServiceLocator) locator).initServices(services);
        }
    }

    public void configSessionFactory(
            Map<Spi, Map<Class<? extends Provider>, Map<String, Class<? extends ProviderFactory>>>> factories,
            Map<Class<? extends Provider>, String> defaultProviders,
            Map<String, ProviderFactory> preConfiguredProviders,
            List<ClasspathThemeProviderFactory.ThemesRepresentation> themes) {
        QuarkusIAMShieldSessionFactory.setInstance(new QuarkusIAMShieldSessionFactory(factories, defaultProviders, preConfiguredProviders, themes));
    }

    public void setDefaultUserProfileConfiguration(UPConfig configuration) {
        DeclarativeUserProfileProviderFactory.setDefaultConfig(configuration);
    }

    public HibernateOrmIntegrationRuntimeInitListener createUserDefinedUnitListener(String name) {
        return propertyCollector -> {
            try (InstanceHandle<AgroalDataSource> instance = Arc.container().instance(
                    AgroalDataSource.class, new DataSource() {
                        @Override public Class<? extends Annotation> annotationType() {
                            return DataSource.class;
                        }

                        @Override public String value() {
                            return name;
                        }
                    })) {
                propertyCollector.accept(AvailableSettings.DATASOURCE, instance.get());
            }
        };
    }

    public HibernateOrmIntegrationRuntimeInitListener createDefaultUnitListener() {
        return propertyCollector -> propertyCollector.accept(AvailableSettings.DEFAULT_SCHEMA, Configuration.getConfigValue(DatabaseOptions.DB_SCHEMA).getValue());
    }

    public void setCryptoProvider(FipsMode fipsMode) {
        String cryptoProvider = fipsMode.getProviderClassName();

        try {
            CryptoIntegration.setProvider(
                    (CryptoProvider) Thread.currentThread().getContextClassLoader().loadClass(cryptoProvider).getDeclaredConstructor().newInstance());
        } catch (ClassNotFoundException | NoClassDefFoundError cause) {
            if (fipsMode.isFipsEnabled()) {
                throw new RuntimeException("Failed to configure FIPS. Make sure you have added the Bouncy Castle FIPS dependencies to the 'providers' directory.");
            }
            throw new RuntimeException("Unexpected error when configuring the crypto provider: " + cryptoProvider, cause);
        } catch (Exception cause) {
            throw new RuntimeException("Unexpected error when configuring the crypto provider: " + cryptoProvider, cause);
        }
    }

    public void configureProtoStreamSchemas(List<SerializationContextInitializer> schemas) {
        Marshalling.setSchemas(schemas);
    }
}
