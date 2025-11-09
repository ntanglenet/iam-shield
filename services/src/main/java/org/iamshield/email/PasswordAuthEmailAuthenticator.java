package org.iamshield.email;

import jakarta.mail.MessagingException;
import jakarta.mail.Transport;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.vault.VaultStringSecret;

import java.util.Map;

public class PasswordAuthEmailAuthenticator implements EmailAuthenticator {

    @Override
    public void connect(IAMShieldSession session, Map<String, String> config, Transport transport) throws EmailException {
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(config.get("password"))) {
            transport.connect(config.get("user"), vaultStringSecret.get().orElse(config.get("password")));
        } catch (MessagingException e) {
            throw new EmailException("Password based SMTP connect failed", e);
        }
    }

}
