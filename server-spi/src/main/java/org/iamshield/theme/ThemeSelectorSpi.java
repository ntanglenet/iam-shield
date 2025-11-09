package org.iamshield.theme;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class ThemeSelectorSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "themeSelector";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return ThemeSelectorProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return ThemeSelectorProviderFactory.class;
    }
}
