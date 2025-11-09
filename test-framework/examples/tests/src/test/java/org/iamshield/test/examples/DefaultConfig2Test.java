package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;

import java.util.List;

@IAMShieldIntegrationTest
public class DefaultConfig2Test {

    @InjectAdminClient
    IAMShield adminClient;

    @Test
    public void testAdminClient() {
        List<RealmRepresentation> realms = adminClient.realms().findAll();
        Assertions.assertFalse(realms.isEmpty());
    }

}
