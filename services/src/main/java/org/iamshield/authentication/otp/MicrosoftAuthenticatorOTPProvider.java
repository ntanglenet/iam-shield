package org.iamshield.authentication.otp;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.OTPPolicy;

public class MicrosoftAuthenticatorOTPProvider implements OTPApplicationProviderFactory, OTPApplicationProvider {

    @Override
    public OTPApplicationProvider create(IAMShieldSession session) {
        return this;
    }

    @Override
    public String getId() {
        return "microsoft-authenticator";
    }

    @Override
    public String getName() {
        return "totpAppMicrosoftAuthenticatorName";
    }

    @Override
    public boolean supports(OTPPolicy policy) {
        if (policy.getDigits() != 6) {
            return false;
        }

        if (!policy.getAlgorithm().equals("HmacSHA1")) {
            return false;
        }

        return policy.getType().equals("totp") && policy.getPeriod() == 30;
    }

    @Override
    public void close() {
    }

}
