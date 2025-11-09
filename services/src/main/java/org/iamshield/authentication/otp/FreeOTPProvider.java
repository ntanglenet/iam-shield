package org.iamshield.authentication.otp;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.OTPPolicy;

public class FreeOTPProvider implements OTPApplicationProviderFactory, OTPApplicationProvider {

    @Override
    public OTPApplicationProvider create(IAMShieldSession session) {
        return this;
    }

    @Override
    public String getId() {
        return "freeotp";
    }

    @Override
    public String getName() {
        return "totpAppFreeOTPName";
    }

    @Override
    public boolean supports(OTPPolicy policy) {
        return true;
    }

    @Override
    public void close() {
    }

}
