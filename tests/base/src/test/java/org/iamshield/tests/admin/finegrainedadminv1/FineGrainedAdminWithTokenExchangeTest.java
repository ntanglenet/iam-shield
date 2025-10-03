package org.iamshield.tests.admin.finegrainedadminv1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.common.Profile;
import org.iamshield.models.Constants;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

@IAMShieldIntegrationTest(config = FineGrainedAdminWithTokenExchangeTest.FineGrainedWithTokenExchangeServerConf.class)
public class FineGrainedAdminWithTokenExchangeTest extends AbstractFineGrainedAdminTest {

    /**
     * KEYCLOAK-7406
     */
    @Test
    public void testWithTokenExchange() {
        String exchanged = checkTokenExchange(true);
        try (IAMShield client = adminClientFactory.create()
                .realm("master").authorization(exchanged).clientId(Constants.ADMIN_CLI_CLIENT_ID).build()) {
            Assertions.assertNotNull(client.realm("master").roles().get("offline_access"));
        }
    }

    public static class FineGrainedWithTokenExchangeServerConf implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            config.features(Profile.Feature.TOKEN_EXCHANGE, Profile.Feature.ADMIN_FINE_GRAINED_AUTHZ);

            return config;
        }
    }
}
