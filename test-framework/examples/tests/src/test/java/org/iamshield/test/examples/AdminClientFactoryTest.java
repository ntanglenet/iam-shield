package org.iamshield.test.examples;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.testframework.admin.AdminClientBuilder;
import org.iamshield.testframework.admin.AdminClientFactory;
import org.iamshield.testframework.annotations.InjectAdminClientFactory;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.realm.ManagedRealm;

@IAMShieldIntegrationTest
public class AdminClientFactoryTest {

    @InjectRealm(config = RealmSpecificAdminClientTest.RealmWithClientAndUser.class)
    ManagedRealm realm;

    @InjectAdminClientFactory(lifecycle = LifeCycle.METHOD)
    AdminClientFactory adminClientFactory;

    static IAMShield AUTO_CLOSE_INSTANCE;

    @AfterAll
    public static void checkClosed() {
        Assertions.assertThrows(IllegalStateException.class, () -> AUTO_CLOSE_INSTANCE.realms().findAll());
    }

    @Test
    public void testAdminClientFactory() {
        try (IAMShield keycloak = createBuilder().build()) {
            Assertions.assertNotNull(keycloak.realm(realm.getName()).toRepresentation());
        }
        AUTO_CLOSE_INSTANCE = createBuilder().autoClose().build();
    }

    private AdminClientBuilder createBuilder() {
        return adminClientFactory.create()
                .realm(realm.getName())
                .clientId("myclient")
                .clientSecret("mysecret")
                .username("myadmin")
                .password("mypassword");
    }

}
