package org.iamshield.device;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderFactory;

public interface DeviceRepresentationProviderFactory extends ProviderFactory<DeviceRepresentationProvider> {

    @Override
    default void init(Config.Scope config) {
    }

    @Override
    default void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    default void close() {
    }
}
