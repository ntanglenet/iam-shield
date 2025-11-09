package org.iamshield.testsuite.util;

import org.iamshield.common.crypto.FipsMode;
import org.iamshield.credential.hash.Pbkdf2Sha512PassHashProviFactory;
import org.iamshield.crypto.hash.Argon2Parameters;
import org.iamshield.crypto.hash.Argon2PasswordHashProviderFactory;
import org.iamshield.testsuite.arquillian.AuthServerTestEnricher;

public class DefaultPasswordHash {

    public static String getDefaultAlgorithm() {
        return notFips() ? Argon2PasswordHashProviderFactory.ID : Pbkdf2Sha512PassHashProviFactory.ID;
    }

    public static int getDefaultIterations() {
        return notFips() ? Argon2Parameters.DEFAULT_ITERATIONS : Pbkdf2Sha512PassHashProviFactory.DEFAULT_ITERATIONS;
    }

    private static boolean notFips() {
        return AuthServerTestEnricher.AUTH_SERVER_FIPS_MODE == FipsMode.DISABLED;
    }

}
