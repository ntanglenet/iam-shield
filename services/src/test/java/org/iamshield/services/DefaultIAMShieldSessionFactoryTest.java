package org.iamshield.services;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;
import org.iamshield.vault.VaultProvider;

import static org.junit.Assert.assertFalse;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class DefaultIAMShieldSessionFactoryTest {

    private DummyConfigurationProvider config;
    private DummySpi spi;

    @Before
    public void before() {
        config = new DummyConfigurationProvider();
        Config.init(config);
    }

    @After
    public void after() {
        Config.init(new Config.SystemPropertiesConfigProvider());
    }

    @Test
    public void testProviderInitialization() {
        DefaultIAMShieldSessionFactory factory = new DefaultIAMShieldSessionFactory() {

            @Override
            public IAMShieldSession create() {
                return null;
            }
        };

        Map<String, ProviderFactory> dependants = Map.of("two", new DummyProviderFactory("two", 2) {
            @Override
            public Set<Class<? extends Provider>> dependsOn() {
                return Set.of(VaultProvider.class);
            }
        }, "one", new DummyProviderFactory("one", 0) {
            @Override
            public Set<Class<? extends Provider>> dependsOn() {
                return Set.of(VaultProvider.class);
            }
        });

        Map<String, ProviderFactory> vault = Map.of("three", new DummyVaultProviderFactory("three", 3) {
            boolean init;

            @Override
            public void postInit(IAMShieldSessionFactory factory) {
                assertFalse(init);
                init = true;
            }
        });

        factory.initProviderFactories(false, Map.of(Provider.class, dependants, VaultProvider.class, vault));
    }

    @Test
    public void defaultProviderFromConfigTest() {
        Map<String, ProviderFactory> map = new HashMap<>(Map.of(
                "two", new DummyProviderFactory("two", 2),
                "one", new DummyProviderFactory("one", 0),
                "three", new DummyProviderFactory("three", 3)));
        spi = new DummySpi();

        // Default provider configured
        config.defaultProvider = "one";
        Assert.assertEquals("one", DefaultIAMShieldSessionFactory.resolveDefaultProvider(map, spi));

        // Highest priority selected
        config.defaultProvider = null;
        Assert.assertEquals("three", DefaultIAMShieldSessionFactory.resolveDefaultProvider(map, spi));

        // No default, with order=0
        map.values().stream().forEach(p -> ((DummyProviderFactory) p).order = 0);
        Assert.assertNull(DefaultIAMShieldSessionFactory.resolveDefaultProvider(map, spi));

        // Provider with id=default selected
        map.put("default", new DummyProviderFactory("default", 0));
        Assert.assertEquals("default", DefaultIAMShieldSessionFactory.resolveDefaultProvider(map, spi));

        // Default set if single provider exists
        map.remove("default");
        map.remove("two");
        map.remove("three");
        Assert.assertEquals("one", DefaultIAMShieldSessionFactory.resolveDefaultProvider(map, spi));

        // Throw error if default configured not found
        config.defaultProvider = "nosuch";
        try {
            DefaultIAMShieldSessionFactory.resolveDefaultProvider(map, spi);
            Assert.fail("Expected exception");
        } catch (RuntimeException e) {
            Assert.assertEquals("Failed to find provider nosuch for dummy", e.getMessage());
        }
    }

    private class DummyConfigurationProvider implements Config.ConfigProvider {

        String defaultProvider;

        @Override
        public String getProvider(String spi) {
            return null;
        }

        @Override
        public String getDefaultProvider(String spi) {
            return defaultProvider;
        }

        @Override
        public Config.Scope scope(String... scope) {
            return null;
        }
    }

    private class DummyProviderFactory extends SimpleProviderFactory<Provider> {

        public DummyProviderFactory(String id, int order) {
            super(id, order);
        }

    }

    private class DummyVaultProviderFactory extends SimpleProviderFactory<VaultProvider> {

        public DummyVaultProviderFactory(String id, int order) {
            super(id, order);
        }

    }

    private class SimpleProviderFactory<T extends Provider> implements ProviderFactory<T> {

        String id;
        int order;

        public SimpleProviderFactory(String id, int order) {
            this.id = id;
            this.order = order;
        }

        @Override
        public T create(IAMShieldSession session) {
            return null;
        }

        @Override
        public void init(Config.Scope config) {
        }

        @Override
        public void postInit(IAMShieldSessionFactory factory) {
        }

        @Override
        public void close() {
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public int order() {
            return order;
        }
    }

    private class DummySpi implements Spi {

        @Override
        public boolean isInternal() {
            return false;
        }

        @Override
        public String getName() {
            return "dummy";
        }

        @Override
        public Class<? extends Provider> getProviderClass() {
            return null;
        }

        @Override
        public Class<? extends ProviderFactory> getProviderFactoryClass() {
            return null;
        }
    }

}
