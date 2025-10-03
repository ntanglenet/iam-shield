package org.iamshield.infinispan.compatibility;

import java.util.Map;
import java.util.stream.Stream;

import org.infinispan.commons.util.Version;
import org.iamshield.Config;
import org.iamshield.compatibility.AbstractCompatibilityMetadataProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.spi.infinispan.CacheEmbeddedConfigProviderSpi;
import org.iamshield.spi.infinispan.impl.embedded.DefaultCacheEmbeddedConfigProviderFactory;

public class CachingEmbeddedMetadataProvider extends AbstractCompatibilityMetadataProvider {

    public CachingEmbeddedMetadataProvider() {
        super(CacheEmbeddedConfigProviderSpi.SPI_NAME, DefaultCacheEmbeddedConfigProviderFactory.PROVIDER_ID);
    }

    @Override
    protected boolean isEnabled(Config.Scope scope) {
        return InfinispanUtils.isEmbeddedInfinispan();
    }

    @Override
    public Map<String, String> customMeta() {
        return Map.of(
              "version", Version.getVersion(),
              "jgroupsVersion", org.jgroups.Version.printVersion()
        );
    }

    @Override
    public Stream<String> configKeys() {
        return Stream.of(DefaultCacheEmbeddedConfigProviderFactory.CONFIG, DefaultCacheEmbeddedConfigProviderFactory.STACK);
    }
}
