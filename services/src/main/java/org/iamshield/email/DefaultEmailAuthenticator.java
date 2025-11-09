package org.iamshield.email;

import jakarta.mail.MessagingException;
import jakarta.mail.Transport;
import org.iamshield.models.IAMShieldSession;

import java.util.Map;

public class DefaultEmailAuthenticator implements EmailAuthenticator {

    @Override
    public void connect(IAMShieldSession session, Map<String, String> config, Transport transport) throws EmailException {
        try {
            transport.connect();
        } catch (MessagingException e) {
            throw new EmailException("Non authenticated connect failed", e);
        }
    }
}
