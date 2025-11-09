package org.iamshield.cookie;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class CookieSpi implements Spi {
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "cookie";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return CookieProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return CookieProviderFactory.class;
    }
}
