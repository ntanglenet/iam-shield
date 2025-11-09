package org.iamshield.tests.admin;

import org.junit.jupiter.api.Test;
import org.iamshield.TokenVerifier;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.crypto.Algorithm;
import org.iamshield.representations.AccessToken;
import org.iamshield.representations.AccessTokenResponse;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.ManagedRealm;

import static org.junit.jupiter.api.Assertions.assertEquals;

@IAMShieldIntegrationTest
public class AdminSignatureAlgorithmTest {

    @InjectAdminClient
    IAMShield admin;

    @InjectRealm(attachTo = "master")
    ManagedRealm masterRealm;

    @Test
    public void changeRealmTokenAlgorithm() throws Exception {
        masterRealm.updateWithCleanup(r -> r.defaultSignatureAlgorithm(Algorithm.ES256));

        admin.tokenManager().invalidate(admin.tokenManager().getAccessTokenString());
        AccessTokenResponse accessToken = admin.tokenManager().getAccessToken();
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(accessToken.getToken(), AccessToken.class);
        assertEquals(Algorithm.ES256, verifier.getHeader().getAlgorithm().name());
    }
}
