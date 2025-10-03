package org.iamshield.authentication.otp;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderFactory;

public interface OTPApplicationProviderFactory extends ProviderFactory<OTPApplicationProvider> {

    @Override
    default void init(Config.Scope config) {
    }

    @Override
    default void postInit(IAMShieldSessionFactory factory) {
    }

}
