package org.iamshield.cache;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class AlternativeLookupSPI implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "alternativeLookup";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return AlternativeLookupProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return AlternativeLookupProviderFactory.class;
    }
}
