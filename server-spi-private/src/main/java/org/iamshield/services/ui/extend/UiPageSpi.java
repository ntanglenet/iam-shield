package org.iamshield.services.ui.extend;

import org.iamshield.common.Profile;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class UiPageSpi implements Spi {
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "ui-page";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return UiPageProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return UiPageProviderFactory.class;
    }

    @Override
    public boolean isEnabled() {
        return Profile.isFeatureEnabled(Profile.Feature.DECLARATIVE_UI);
    }
}
