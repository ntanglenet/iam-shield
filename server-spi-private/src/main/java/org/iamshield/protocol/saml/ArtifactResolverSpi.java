package org.iamshield.protocol.saml;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

/**
 *
 */
public class ArtifactResolverSpi implements Spi {
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "saml-artifact-resolver";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return ArtifactResolver.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return ArtifactResolverFactory.class;
    }
}
