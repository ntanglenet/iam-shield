package org.iamshield.authentication.otp;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.OTPPolicy;

public class GoogleAuthenticatorProvider implements OTPApplicationProviderFactory, OTPApplicationProvider {

    @Override
    public OTPApplicationProvider create(IAMShieldSession session) {
        return this;
    }

    @Override
    public String getId() {
        return "google";
    }

    @Override
    public String getName() {
        return "totpAppGoogleName";
    }

    @Override
    public boolean supports(OTPPolicy policy) {
        if (policy.getType().equals("totp")) {
            return policy.getPeriod() == 30;
        }
        return true;
    }

    @Override
    public void close() {
    }

}
