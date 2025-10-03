package org.iamshield.email;

import jakarta.mail.Transport;
import org.iamshield.models.IAMShieldSession;

import java.util.Map;

public interface EmailAuthenticator {

    void connect(IAMShieldSession session, Map<String, String> config, Transport transport) throws EmailException;

    enum AuthenticatorType {
        NONE,
        BASIC,
        TOKEN
    }
}


