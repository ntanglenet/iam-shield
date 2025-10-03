package org.iamshield.tests.infinispan;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

@IAMShieldIntegrationTest(config = InfinispanXMLBackwardCompatibilityTest.ServerConfigWithCustomInfinispanXML.class)
public class InfinispanXMLBackwardCompatibilityTest {

    private static final String CONFIG_FILE = "/embedded-infinispan-config/infinispan-xml-kc26.xml";

    @InjectRealm
    ManagedRealm realm;

    @Test
    void testKeycloakStartedSuccessfullyWithOlderInfinispanXML() {
        RealmRepresentation representation = realm.admin().toRepresentation();
        Assertions.assertNotNull(representation);
    }


    public static class ServerConfigWithCustomInfinispanXML implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            return config.cacheConfigFile(CONFIG_FILE);
        }
    }
}
