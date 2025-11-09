package org.iamshield.device;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.Provider;
import org.iamshield.representations.account.DeviceRepresentation;

public interface DeviceRepresentationProvider extends Provider {

    DeviceRepresentation deviceRepresentation();

    @Override
    default void close() {
    }
}
