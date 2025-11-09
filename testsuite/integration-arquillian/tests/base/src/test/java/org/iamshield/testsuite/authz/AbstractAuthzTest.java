package org.iamshield.testsuite.authz;

import org.junit.BeforeClass;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.jose.jws.JWSInputException;
import org.iamshield.representations.AccessToken;
import org.iamshield.testsuite.AbstractIAMShieldTest;
import org.iamshield.testsuite.ProfileAssume;

import static org.iamshield.common.Profile.Feature.AUTHORIZATION;

/**
 * @author mhajas
 */
public abstract class AbstractAuthzTest extends AbstractIAMShieldTest {

    @BeforeClass
    public static void enabled() {
        ProfileAssume.assumeFeatureEnabled(AUTHORIZATION);
    }

    protected AccessToken toAccessToken(String rpt) {
        AccessToken accessToken;

        try {
            accessToken = new JWSInput(rpt).readJsonContent(AccessToken.class);
        } catch (JWSInputException cause) {
            throw new RuntimeException("Failed to deserialize RPT", cause);
        }
        return accessToken;
    }
}
