package org.iamshield.theme.freemarker;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class FreeMarkerSPI implements Spi {
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "freemarker";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return FreeMarkerProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return FreeMarkerProviderFactory.class;
    }
}
