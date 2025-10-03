package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.jose.jws.JWSInputException;
import org.iamshield.models.AdminRoles;
import org.iamshield.models.Constants;
import org.iamshield.representations.AccessToken;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.MappingsRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.RealmConfig;
import org.iamshield.testframework.realm.RealmConfigBuilder;

import java.util.List;

@IAMShieldIntegrationTest
public class RealmSpecificAdminClientTest {

    @InjectRealm(config = RealmWithClientAndUser.class)
    ManagedRealm realm;

    @InjectAdminClient(ref = "bootstrap-client")
    IAMShield bootstrapAdminClient;

    @InjectAdminClient(mode = InjectAdminClient.Mode.MANAGED_REALM, client = "myclient", user = "myadmin")
    IAMShield realmAdminClient;

    @Test
    public void testAdminClientIssuers() throws JWSInputException {
        AccessToken bootstrapAccessToken = new JWSInput(bootstrapAdminClient.tokenManager().getAccessToken().getToken()).readJsonContent(AccessToken.class);
        Assertions.assertTrue(bootstrapAccessToken.getIssuer().endsWith("/realms/master"));

        AccessToken realmAccessToken = new JWSInput(realmAdminClient.tokenManager().getAccessToken().getToken()).readJsonContent(AccessToken.class);
        Assertions.assertTrue(realmAccessToken.getIssuer().endsWith("/realms/" + realm.getName()));
    }

    @Test
    public void testRealmWithClientAndUser() {
        RealmResource realmResource = realmAdminClient.realms().realm(realm.getName());

        List<ClientRepresentation> clients = realmResource.clients().findByClientId("myclient");
        Assertions.assertEquals(1, clients.size());

        ClientRepresentation client = clients.get(0);
        Assertions.assertTrue(client.isEnabled());
        Assertions.assertTrue(client.isDirectAccessGrantsEnabled());
        Assertions.assertEquals("mysecret", client.getSecret());

        List<UserRepresentation> users = realm.admin().users().search("myadmin");
        Assertions.assertEquals(1, users.size());

        UserRepresentation user = users.get(0);
        Assertions.assertTrue(user.isEnabled());
        Assertions.assertEquals("My", user.getFirstName());
        Assertions.assertEquals("Admin", user.getLastName());
        Assertions.assertEquals("myadmin@localhost", user.getEmail());
        Assertions.assertTrue(user.isEmailVerified());

        MappingsRepresentation roles = realmResource.users().get(user.getId()).roles().getAll();
        Assertions.assertEquals(1, roles.getClientMappings().get(Constants.REALM_MANAGEMENT_CLIENT_ID).getMappings().size());
    }

    public static class RealmWithClientAndUser implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            realm.addClient("myclient")
                    .secret("mysecret")
                    .directAccessGrantsEnabled(true);

            realm.addUser("myadmin")
                    .name("My", "Admin")
                    .email("myadmin@localhost")
                    .emailVerified(true)
                    .password("mypassword")
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.REALM_ADMIN);

            return realm;
        }
    }

}
