/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.jgroups.certificates;

import java.io.File;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.iamshield.Config;
import org.iamshield.config.CachingOptions;
import org.iamshield.config.Option;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.spi.infinispan.JGroupsCertificateProvider;
import org.iamshield.spi.infinispan.JGroupsCertificateProviderFactory;
import org.iamshield.storage.configuration.ServerConfigStorageProvider;

/**
 * The default implementation for {@link JGroupsCertificateProvider}.
 * <p>
 * This implementation will return different implementation based on the current configuration.
 *
 * @see DatabaseJGroupsCertificateProvider
 * @see FileJGroupsCertificateProvider
 */
public class DefaultJGroupsCertificateProviderFactory implements JGroupsCertificateProviderFactory {

    public static final String PROVIDER_ID = "default";

    // config
    public static final String ENABLED = "enabled";
    private static final String ROTATION = "rotation";
    private static final String KEYSTORE_PATH = "keystoreFile";
    private static final String KEYSTORE_PASSWORD = "keystorePassword";
    private static final String TRUSTSTORE_PATH = "truststoreFile";
    private static final String TRUSTSTORE_PASSWORD = "truststorePassword";

    // shared state
    private volatile JGroupsCertificateProvider provider;
    private volatile Config.Scope configuration;

    @Override
    public JGroupsCertificateProvider create(IAMShieldSession session) {
        if (provider == null) {
            postInit(session.getIAMShieldSessionFactory());
        }
        return provider;
    }

    @Override
    public void init(Config.Scope config) {
        this.configuration = config;
    }

    @Override
    public synchronized void postInit(IAMShieldSessionFactory factory) {
        if (provider != null) {
            return;
        }
        provider = createProvider(factory);
    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(ServerConfigStorageProvider.class);
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        var builder = ProviderConfigurationBuilder.create();
        addEnabledOption(builder);
        addRotationOption(builder);
        addPropertyForFile(builder, CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE, KEYSTORE_PATH);
        addPropertyForFile(builder, CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE, TRUSTSTORE_PATH);
        addPropertyForPassword(builder, CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD, KEYSTORE_PASSWORD);
        addPropertyForPassword(builder, CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD, TRUSTSTORE_PASSWORD);
        return builder.build();
    }

    private JGroupsCertificateProvider createProvider(IAMShieldSessionFactory factory) {
        if (!configuration.getBoolean(ENABLED, Boolean.FALSE)) {
            return JGroupsCertificateProvider.DISABLED;
        }
        if (isKeystoreOrTruststoreConfigured()) {
            return FileJGroupsCertificateProvider.create(
                  requireConfigurationAndFile(KEYSTORE_PATH, CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE),
                  requireConfiguration(KEYSTORE_PASSWORD, CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD),
                  requireConfigurationAndFile(TRUSTSTORE_PATH, CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE),
                  requireConfiguration(TRUSTSTORE_PASSWORD, CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD)
            );
        }
        return DatabaseJGroupsCertificateProvider.create(factory, Duration.ofDays(requireRotationInDays()));
    }

    private boolean isKeystoreOrTruststoreConfigured() {
        return configuration.get(KEYSTORE_PATH) != null || configuration.get(TRUSTSTORE_PATH) != null;
    }

    private long requireRotationInDays() {
        var value = configuration.getLong(ROTATION);
        if (value == null) {
            throw new RuntimeException("Property '%s' required but not specified.".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ROTATION.getKey()));
        }
        return value;
    }

    private String requireConfigurationAndFile(String key, Option<?> option) {
        var value = requireConfiguration(key, option);
        if (!new File(value).exists()) {
            throw new RuntimeException("Property '%s' file '%s' does not exist.".formatted(key, value));
        }
        return value;
    }

    private String requireConfiguration(String key, Option<?> option) {
        var value = configuration.get(key);
        if (value == null) {
            throw new RuntimeException("Property '%s' required but not specified".formatted(option.getKey()));
        }
        return value;
    }

    private static void addEnabledOption(ProviderConfigurationBuilder builder) {
        propertyForOption(builder, CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED)
                .name(ENABLED)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("enabled")
                .add();
    }

    private static void addRotationOption(ProviderConfigurationBuilder builder) {
        propertyForOption(builder, CachingOptions.CACHE_EMBEDDED_MTLS_ROTATION)
                .name(ROTATION)
                .type(ProviderConfigProperty.INTEGER_TYPE)
                .label("days")
                .add();
    }

    private static void addPropertyForFile(ProviderConfigurationBuilder builder, Option<?> option, String name) {
        propertyForOption(builder, option)
                .name(name)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("file")
                .add();
    }

    private static void addPropertyForPassword(ProviderConfigurationBuilder builder, Option<?> option, String name) {
        propertyForOption(builder, option)
                .name(name)
                .type(ProviderConfigProperty.PASSWORD)
                .label("password")
                .secret(true)
                .add();
    }

    private static ProviderConfigurationBuilder.ProviderConfigPropertyBuilder propertyForOption(ProviderConfigurationBuilder builder, Option<?> option) {
        var property = builder.property();
        option.getDefaultValue().ifPresent(property::defaultValue);
        property.helpText(option.getDescription());
        return property;
    }
}
