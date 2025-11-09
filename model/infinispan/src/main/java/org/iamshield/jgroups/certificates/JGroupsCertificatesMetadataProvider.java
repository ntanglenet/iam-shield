package org.iamshield.jgroups.certificates;

import java.util.stream.Stream;

import org.iamshield.Config;
import org.iamshield.compatibility.AbstractCompatibilityMetadataProvider;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.spi.infinispan.JGroupsCertificateProviderSpi;

public class JGroupsCertificatesMetadataProvider extends AbstractCompatibilityMetadataProvider {

    public JGroupsCertificatesMetadataProvider() {
        super(JGroupsCertificateProviderSpi.SPI_NAME, DefaultJGroupsCertificateProviderFactory.PROVIDER_ID);
    }

    @Override
    protected boolean isEnabled(Config.Scope scope) {
        return InfinispanUtils.isEmbeddedInfinispan();
    }

    @Override
    public Stream<String> configKeys() {
        return Stream.of(DefaultJGroupsCertificateProviderFactory.ENABLED);
    }
}
