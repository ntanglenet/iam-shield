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

package org.iamshield.spi.infinispan.impl.embedded;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import io.micrometer.core.instrument.Metrics;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.cache.StatisticsConfigurationBuilder;
import org.infinispan.configuration.global.ShutdownHookBehavior;
import org.infinispan.configuration.parsing.ConfigurationBuilderHolder;
import org.infinispan.configuration.parsing.ParserRegistry;
import org.infinispan.metrics.config.MicrometerMeterRegisterConfigurationBuilder;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.config.CachingOptions;
import org.iamshield.config.MetricsOptions;
import org.iamshield.infinispan.module.configuration.global.IAMShieldConfigurationBuilder;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.marshalling.Marshalling;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.spi.infinispan.CacheEmbeddedConfigProvider;
import org.iamshield.spi.infinispan.CacheEmbeddedConfigProviderFactory;
import org.iamshield.spi.infinispan.JGroupsCertificateProvider;
import org.iamshield.spi.infinispan.impl.Util;

import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.ALL_CACHES_NAME;
import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.CLUSTERED_MAX_COUNT_CACHES;
import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.CLUSTERED_CACHE_NUM_OWNERS;
import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.LOCAL_CACHE_NAMES;
import static org.iamshield.spi.infinispan.impl.embedded.JGroupsConfigurator.createJGroupsProperties;

/**
 * The default implementation of {@link CacheEmbeddedConfigProviderFactory}.
 * <p>
 * It builds a {@link ConfigurationBuilderHolder} based on the Keycloak configuration.
 * <p>
 * Advanced users may extend this class and overwrite the method {@link #createConfiguration(IAMShieldSessionFactory)}.
 * They have access to the {@link ConfigurationBuilderHolder}, and they can modify it as needed for their custom
 * providers.
 */
public class DefaultCacheEmbeddedConfigProviderFactory implements CacheEmbeddedConfigProviderFactory, CacheEmbeddedConfigProvider {

    private static final Logger logger = Logger.getLogger(MethodHandles.lookup().lookupClass());

    public static final String PROVIDER_ID = "default";

    // Configuration
    public static final String CONFIG = "configFile";
    public static final String CONFIG_MUTATE = "configMutate";
    public static final String TRACING = "tracingEnabled";
    private static final String HISTOGRAMS = "metricsHistogramsEnabled";
    public static final String STACK = "stack";
    public static final String NODE_NAME = "nodeName";
    public static final String SITE_NAME = "siteName";
    public static final String MACHINE_NAME = "machineName";
    public static final String RACK_NAME = "rackName";

    private volatile ConfigurationBuilderHolder builderHolder;
    private volatile Config.Scope keycloakConfig;

    @Override
    public CacheEmbeddedConfigProvider create(IAMShieldSession session) {
        lazyInit(session.getIAMShieldSessionFactory());
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        this.keycloakConfig = config;
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        lazyInit(factory);
    }

    @Override
    public ConfigurationBuilderHolder configuration() {
        return builderHolder;
    }

    @Override
    public void close() {
        //no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        var builder = ProviderConfigurationBuilder.create();
        Util.copyFromOption(builder, CONFIG, "file", ProviderConfigProperty.STRING_TYPE, CachingOptions.CACHE_CONFIG_FILE, false);
        Util.copyFromOption(builder, HISTOGRAMS, "enabled", ProviderConfigProperty.BOOLEAN_TYPE, CachingOptions.CACHE_METRICS_HISTOGRAMS_ENABLED, false);
        Stream.concat(Arrays.stream(LOCAL_CACHE_NAMES), Arrays.stream(CLUSTERED_MAX_COUNT_CACHES))
                .forEach(name -> Util.copyFromOption(builder, CacheConfigurator.maxCountConfigKey(name), "max-count", ProviderConfigProperty.INTEGER_TYPE, CachingOptions.maxCountOption(name), false));
        Arrays.stream(CLUSTERED_CACHE_NUM_OWNERS)
                .forEach(name -> builder.property()
                        .name(CacheConfigurator.numOwnerConfigKey(name))
                        .helpText("Sets the number of owners for the %s distributed cache. It defines the number of copies of your data in the cluster.".formatted(name))
                        .label("owners")
                        .type(ProviderConfigProperty.INTEGER_TYPE)
                        .add());
        createTopologyProperties(builder);
        createJGroupsProperties(builder);
        return builder.build();
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(JGroupsCertificateProvider.class);
    }

    private void lazyInit(IAMShieldSessionFactory factory) {
        if (builderHolder != null) {
            return;
        }
        synchronized (this) {
            if (builderHolder != null) {
                return;
            }
            try {
                builderHolder = createConfiguration(factory);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    protected ConfigurationBuilderHolder createConfiguration(IAMShieldSessionFactory factory) throws IOException {
        var holder = parseConfiguration(keycloakConfig, factory);
        if (InfinispanUtils.isRemoteInfinispan()) {
            return configureMultiSite(holder, keycloakConfig);
        }
        if (Profile.isFeatureEnabled(Profile.Feature.PERSISTENT_USER_SESSIONS)) {
            return configureSingleSiteWithPersistentSessions(holder, keycloakConfig, factory);
        }
        return configureSingleSiteWithVolatileSessions(holder, keycloakConfig, factory);
    }

    private static ConfigurationBuilderHolder configureSingleSiteWithVolatileSessions(ConfigurationBuilderHolder holder, Config.Scope keycloakConfig, IAMShieldSessionFactory factory) {
        singleSiteConfiguration(keycloakConfig, holder, factory);
        CacheConfigurator.configureSessionsCachesForVolatileSessions(holder);
        return holder;
    }

    private static ConfigurationBuilderHolder configureSingleSiteWithPersistentSessions(ConfigurationBuilderHolder holder, Config.Scope keycloakConfig, IAMShieldSessionFactory factory) {
        singleSiteConfiguration(keycloakConfig, holder, factory);
        CacheConfigurator.configureSessionsCachesForPersistentSessions(holder);
        return holder;
    }

    private static ConfigurationBuilderHolder configureMultiSite(ConfigurationBuilderHolder holder, Config.Scope keycloakConfig) {
        logger.debug("Configuring Infinispan for multi-site deployment");
        CacheConfigurator.removeClusteredCaches(holder);
        CacheConfigurator.checkCachesExist(holder, Arrays.stream(LOCAL_CACHE_NAMES));
        configureMetrics(keycloakConfig, holder);
        // Disable JGroups, not required when the data is stored in the Remote Cache.
        // The existing caches are local and do not require JGroups to work properly.
        holder.getGlobalConfigurationBuilder().nonClusteredDefault();
        return holder;
    }

    private static ConfigurationBuilderHolder parseConfiguration(Config.Scope keycloakConfig, IAMShieldSessionFactory factory) throws IOException {
        var configFile = keycloakConfig.get(CONFIG);
        if (configFile == null) {
            throw new IllegalArgumentException("Option 'configFile' needs to be specified");
        }
        var configPath = Paths.get(configFile);
        var path = configPath.toFile().exists() ?
                configPath.toFile().getAbsolutePath() :
                configPath.getFileName().toString();

        logger.debugf("Parsing Infinispan configuration from file: %s", path);
        var holder = new ParserRegistry(DefaultCacheEmbeddedConfigProviderFactory.class.getClassLoader())
                .parseFile(path);
        // We must disable the Infinispan default ShutdownHook as we manage the EmbeddedCacheManager lifecycle explicitly
        // with #shutdown and multiple calls to EmbeddedCacheManager#stop can lead to Exceptions being thrown.
        holder.getGlobalConfigurationBuilder().shutdown().hookBehavior(ShutdownHookBehavior.DONT_REGISTER);
        Marshalling.configure(holder.getGlobalConfigurationBuilder());
        holder.getGlobalConfigurationBuilder()
                .addModule(IAMShieldConfigurationBuilder.class)
                .setIAMShieldSessionFactory(factory);

        CacheConfigurator.applyDefaultConfiguration(holder, !keycloakConfig.getBoolean(CONFIG_MUTATE, Boolean.FALSE));
        CacheConfigurator.configureLocalCaches(keycloakConfig, holder);
        JGroupsConfigurator.configureTopology(keycloakConfig, holder);
        return holder;
    }

    private static void singleSiteConfiguration(Config.Scope config, ConfigurationBuilderHolder holder, IAMShieldSessionFactory factory) {
        logger.debug("Configuring Infinispan for single-site deployment");
        CacheConfigurator.checkCachesExist(holder, Arrays.stream(ALL_CACHES_NAME));
        CacheConfigurator.configureCacheMaxCount(config, holder, Arrays.stream(CLUSTERED_MAX_COUNT_CACHES));
        CacheConfigurator.configureNumOwners(config, holder);
        CacheConfigurator.validateWorkCacheConfiguration(holder);
        CacheConfigurator.ensureMinimumOwners(holder);
        if (JGroupsConfigurator.isClustered(holder)) {
            IAMShieldModelUtils.runJobInTransaction(factory, session -> JGroupsConfigurator.configureJGroups(config, holder, session));
        }
        configureMetrics(config, holder);
    }

    private static void configureMetrics(Config.Scope keycloakConfig, ConfigurationBuilderHolder holder) {
        //metrics are disabled by default (check MetricsOptions class)
        if (keycloakConfig.root().getBoolean(MetricsOptions.METRICS_ENABLED.getKey(), Boolean.FALSE)) {
            logger.debug("Enabling Infinispan metrics");
            var builder = holder.getGlobalConfigurationBuilder();
            builder.addModule(MicrometerMeterRegisterConfigurationBuilder.class)
                    .meterRegistry(Metrics.globalRegistry);
            builder.cacheContainer().statistics(true);
            builder.metrics()
                    .namesAsTags(true)
                    .histograms(keycloakConfig.getBoolean(HISTOGRAMS, Boolean.FALSE));
            holder.getNamedConfigurationBuilders()
                    .values()
                    .stream()
                    .map(ConfigurationBuilder::statistics)
                    .forEach(StatisticsConfigurationBuilder::enable);
        }
    }

    private static void createTopologyProperties(ProviderConfigurationBuilder builder) {
        builder.property()
                .name(NODE_NAME)
                .helpText("Sets the name of the current node. This is a friendly name to make logs, etc. make more sense.")
                .label("name")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add();
        builder.property()
                .name(SITE_NAME)
                .helpText("The name of the site (availability zone) where this instance runs. It can be set if running Keycloak in different availability zones. Infinispan takes into consideration this value to keep the backup data spread between different sites.")
                .label("name")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add();
        builder.property()
                .name(MACHINE_NAME)
                .helpText("The name of the physical machine where this instance runs. It can be set if multiple Keycloak instances are running in the same physical machines. Infinispan takes into consideration this value to keep the backup data spread between different machines.")
                .label("name")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add();
        builder.property()
                .name(RACK_NAME)
                .helpText("The name of the rack where this instance runs. It can be set if multiple Keycloak instances are running in the same physical rack. Infinispan takes into consideration this value to keep the backup data spread between different racks.")
                .label("name")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add();
    }
}
