package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.common.Profile;
import org.iamshield.representations.info.FeatureRepresentation;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfig;

import java.util.Optional;

@IAMShieldIntegrationTest(config = CustomConfigTest.CustomServerConfig.class)
public class CustomConfigTest {

    @InjectAdminClient
    IAMShield adminClient;

    @Test
    public void testPasskeyFeatureEnabled() {
        Optional<FeatureRepresentation> passKeysFeature = adminClient.serverInfo().getInfo().getFeatures().stream().filter(f -> f.getName().equals(Profile.Feature.PASSKEYS.name())).findFirst();
        Assertions.assertTrue(passKeysFeature.isPresent());
        Assertions.assertTrue(passKeysFeature.get().isEnabled());
    }

    public static class CustomServerConfig implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            return config.features(Profile.Feature.PASSKEYS);
        }

    }

}
