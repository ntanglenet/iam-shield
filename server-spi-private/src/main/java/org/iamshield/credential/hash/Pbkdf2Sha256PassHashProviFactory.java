package org.iamshield.credential.hash;

import org.iamshield.models.IAMShieldSession;

/**
 * PBKDF2 Password Hash provider with HMAC using SHA256
 *
 * @author <a href"mailto:abkaplan07@gmail.com">Adam Kaplan</a>
 */
public class Pbkdf2Sha256PassHashProviFactory extends AbstractPbkdf2PassHashProviFactory implements PasswordHashProviderFactory {

    public static final String ID = "pbkdf2-sha256";

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * Hash iterations for PBKDF2-HMAC-SHA256 according to the <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">Password Storage Cheat Sheet</a>.
     */
    public static final int DEFAULT_ITERATIONS = 600_000;

    @Override
    public PasswordHashProvider create(IAMShieldSession session) {
        return new Pbkdf2PasswordHashProvider(ID, PBKDF2_ALGORITHM, DEFAULT_ITERATIONS, getMaxPaddingLength(), 256);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        return 100;
    }
}
