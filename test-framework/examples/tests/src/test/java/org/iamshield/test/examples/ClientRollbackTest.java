package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.testframework.annotations.InjectClient;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.ClientConfig;
import org.iamshield.testframework.realm.ClientConfigBuilder;
import org.iamshield.testframework.realm.ManagedClient;

import java.util.List;

@IAMShieldIntegrationTest
@TestMethodOrder(MethodOrderer.MethodName.class)
public class ClientRollbackTest {

    @InjectClient(config = ClientWithSingleAttribute.class)
    ManagedClient client;

    @Test
    public void test1UpdateWithRollback() {
        client.updateWithCleanup(u -> u.attribute("one", "two").attribute("two", "two"));
        client.updateWithCleanup(u -> u.adminUrl("http://something"));
        client.updateWithCleanup(u -> u.redirectUris("http://something"));
        client.updateWithCleanup(u -> u.attribute("three", "three"));
    }

    @Test
    public void test2CheckRollback() {
        ClientRepresentation current = client.admin().toRepresentation();

        Assertions.assertEquals("one", current.getAttributes().get("one"));
        Assertions.assertFalse(current.getAttributes().containsKey("two"));
        Assertions.assertFalse(current.getAttributes().containsKey("three"));
        Assertions.assertNull(current.getAdminUrl());
        Assertions.assertTrue(current.getRedirectUris().isEmpty());
    }

    public static class ClientWithSingleAttribute implements ClientConfig {

        @Override
        public ClientConfigBuilder configure(ClientConfigBuilder client) {
            return client.attribute("one", "one");
        }

    }
}
