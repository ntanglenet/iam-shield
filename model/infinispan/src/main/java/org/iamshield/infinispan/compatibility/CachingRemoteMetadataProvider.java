package org.iamshield.infinispan.compatibility;

import java.util.stream.Stream;

import org.iamshield.Config;
import org.iamshield.compatibility.AbstractCompatibilityMetadataProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.spi.infinispan.CacheRemoteConfigProviderSpi;
import org.iamshield.spi.infinispan.impl.remote.DefaultCacheRemoteConfigProviderFactory;

public class CachingRemoteMetadataProvider extends AbstractCompatibilityMetadataProvider {

    public CachingRemoteMetadataProvider() {
        super(CacheRemoteConfigProviderSpi.SPI_NAME, DefaultCacheRemoteConfigProviderFactory.PROVIDER_ID);
    }

    @Override
    protected boolean isEnabled(Config.Scope scope) {
        return InfinispanUtils.isRemoteInfinispan();
    }

    @Override
    protected Stream<String> configKeys() {
        return Stream.of(DefaultCacheRemoteConfigProviderFactory.HOSTNAME, DefaultCacheRemoteConfigProviderFactory.PORT);
    }
}
