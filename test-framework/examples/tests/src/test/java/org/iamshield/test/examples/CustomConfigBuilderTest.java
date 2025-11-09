package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.representations.idm.GroupRepresentation;
import org.iamshield.testframework.annotations.InjectClient;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.InjectUser;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.ClientConfig;
import org.iamshield.testframework.realm.ClientConfigBuilder;
import org.iamshield.testframework.realm.ManagedClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.ManagedUser;
import org.iamshield.testframework.realm.RealmConfig;
import org.iamshield.testframework.realm.RealmConfigBuilder;
import org.iamshield.testframework.realm.UserConfig;
import org.iamshield.testframework.realm.UserConfigBuilder;

import java.util.LinkedList;

@IAMShieldIntegrationTest
public class CustomConfigBuilderTest {

    @InjectRealm(config = CustomRealmConfig.class)
    ManagedRealm realm;

    @InjectClient(config = CustomClientConfig.class)
    ManagedClient client;

    @InjectUser(config = CustomUserConfig.class)
    ManagedUser user;

    @Test
    public void testRealm() {
        Assertions.assertEquals(1, realm.admin().groups().query("mygroup").size());
    }

    @Test
    public void testClient() {
        Assertions.assertTrue(client.admin().toRepresentation().isBearerOnly());
    }

    @Test
    public void testUser() {
        Assertions.assertFalse(user.admin().toRepresentation().isEnabled());
    }

    public static class CustomRealmConfig implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            return realm.update(r -> {
                if (r.getGroups() == null) {
                    r.setGroups(new LinkedList<>());
                }
                GroupRepresentation group = new GroupRepresentation();
                group.setName("mygroup");
                group.setPath("/mygroup");
                r.getGroups().add(group);
            });
        }
    }

    public static class CustomClientConfig implements ClientConfig {

        @Override
        public ClientConfigBuilder configure(ClientConfigBuilder client) {
            return client.update(u -> u.setBearerOnly(true));
        }
    }

    public static class CustomUserConfig implements UserConfig {

        @Override
        public UserConfigBuilder configure(UserConfigBuilder user) {
            return user.update(u -> u.setEnabled(false));
        }
    }

}
