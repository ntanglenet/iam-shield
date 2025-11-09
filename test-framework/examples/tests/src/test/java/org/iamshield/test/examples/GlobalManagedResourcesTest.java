package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.testframework.annotations.InjectClient;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.InjectUser;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.realm.ManagedClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.ManagedUser;

@IAMShieldIntegrationTest
public class GlobalManagedResourcesTest {

    @InjectRealm(lifecycle = LifeCycle.GLOBAL)
    ManagedRealm realm;

    @InjectClient(lifecycle = LifeCycle.GLOBAL)
    ManagedClient client;

    @InjectUser(lifecycle = LifeCycle.GLOBAL)
    ManagedUser user;

    @Test
    public void testCreatedRealm() {
        Assertions.assertEquals("default", realm.getName());
    }

    @Test
    public void testCreatedClient() {
        Assertions.assertEquals("default", client.getClientId());
    }

    @Test
    public void testCreatedUser() {
        Assertions.assertEquals("default", user.getUsername());
    }

}
