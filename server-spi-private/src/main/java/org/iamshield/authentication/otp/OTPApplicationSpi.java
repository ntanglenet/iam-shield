package org.iamshield.authentication.otp;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class OTPApplicationSpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "otp-application";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return OTPApplicationProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return OTPApplicationProviderFactory.class;
    }

}
