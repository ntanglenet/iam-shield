package org.iamshield.authentication.otp;

import org.iamshield.models.OTPPolicy;
import org.iamshield.provider.Provider;

public interface OTPApplicationProvider extends Provider {

    String getName();

    boolean supports(OTPPolicy policy);

}
