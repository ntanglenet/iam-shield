package org.iamshield.encoding;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class ResourceEncodingSpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "resource-encoding";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return ResourceEncodingProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return ResourceEncodingProviderFactory.class;
    }

}
