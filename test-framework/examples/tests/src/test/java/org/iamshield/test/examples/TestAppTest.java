package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.representations.adapters.action.PushNotBeforeAction;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.TestApp;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectTestApp;
import org.iamshield.testframework.realm.ManagedRealm;

@IAMShieldIntegrationTest
public class TestAppTest {

    @InjectOAuthClient(kcAdmin = true)
    OAuthClient oauth;

    @InjectTestApp
    TestApp testApp;

    @InjectRealm
    ManagedRealm managedRealm;

    @Test
    public void testPushNotBefore() throws InterruptedException {
        String clientUuid = managedRealm.admin().clients().findByClientId("test-app").stream().findFirst().get().getId();
        managedRealm.admin().clients().get(clientUuid).pushRevocation();

        PushNotBeforeAction adminPushNotBefore = testApp.kcAdmin().getAdminPushNotBefore();
        Assertions.assertNotNull(adminPushNotBefore);
    }

}
