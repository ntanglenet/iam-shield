package org.iamshield.theme;

import org.iamshield.models.ThemeManager;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class ThemeManagerSpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "themeManager";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return ThemeManager.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return ThemeManagerFactory.class;
    }
}
