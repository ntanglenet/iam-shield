package org.iamshield.device;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class DeviceRepresentationSpi implements Spi {

    public static final String NAME = "deviceRepresentation";
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return DeviceRepresentationProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return DeviceRepresentationProviderFactory.class;
    }

}
