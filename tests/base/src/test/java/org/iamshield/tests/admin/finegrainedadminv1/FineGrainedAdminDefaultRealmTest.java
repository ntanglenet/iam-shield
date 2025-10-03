package org.iamshield.tests.admin.finegrainedadminv1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.authorization.model.Resource;
import org.iamshield.models.AdminRoles;
import org.iamshield.models.ClientModel;
import org.iamshield.models.Constants;
import org.iamshield.models.GroupModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserCredentialModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.services.resources.admin.fgap.AdminPermissionManagement;
import org.iamshield.services.resources.admin.fgap.AdminPermissions;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;

import java.util.LinkedList;
import java.util.List;

@IAMShieldIntegrationTest(config = AbstractFineGrainedAdminTest.FineGrainedAdminServerConf.class)
public class FineGrainedAdminDefaultRealmTest extends AbstractFineGrainedAdminTest {

    // KEYCLOAK-5152
    @Test
    public void testRealmWithComposites() {
        runOnServer.run(FineGrainedAdminDefaultRealmTest::setup5152);

        try (IAMShield realmClient = adminClientFactory.create().realm(REALM_NAME)
                .username("realm-admin").password("password").clientId(Constants.ADMIN_CLI_CLIENT_ID).build()) {
            RoleRepresentation composite = new RoleRepresentation();
            composite.setName("composite");
            composite.setComposite(true);
            realmClient.realm(REALM_NAME).roles().create(composite);
            composite = managedRealm.admin().roles().get("composite").toRepresentation();

            ClientRepresentation client = managedRealm.admin().clients().findByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).get(0);
            RoleRepresentation viewUsers = managedRealm.admin().clients().get(client.getId()).roles().get(AdminRoles.CREATE_CLIENT).toRepresentation();

            List<RoleRepresentation> composites = new LinkedList<>();
            composites.add(viewUsers);
            realmClient.realm(REALM_NAME).rolesById().addComposites(composite.getId(), composites);
        }
    }

    @Test
    public void testRemoveCleanup() {
        runOnServer.run(FineGrainedAdminDefaultRealmTest::setupDeleteTest);
        runOnServer.run(FineGrainedAdminDefaultRealmTest::invokeDelete);
    }

    public static void setup5152(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        ClientModel realmAdminClient = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel realmAdminRole = realmAdminClient.getRole(AdminRoles.REALM_ADMIN);

        UserModel realmUser = session.users().addUser(realm, "realm-admin");
        realmUser.setFirstName("Realm");
        realmUser.setLastName("Admin");
        realmUser.setEmail("realm@admin");
        realmUser.grantRole(realmAdminRole);
        realmUser.setEnabled(true);
        realmUser.credentialManager().updateCredential(UserCredentialModel.password("password"));
    }

    // test role deletion that it cleans up authz objects
    public static void setupDeleteTest(IAMShieldSession session )  {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        RoleModel removedRole = realm.addRole("removedRole");
        ClientModel client = realm.addClient("removedClient");
        RoleModel removedClientRole = client.addRole("removedClientRole");
        GroupModel removedGroup = realm.createGroup("removedGroup");
        AdminPermissionManagement management = AdminPermissions.management(session, realm);
        management.roles().setPermissionsEnabled(removedRole, true);
        management.roles().setPermissionsEnabled(removedClientRole, true);
        management.groups().setPermissionsEnabled(removedGroup, true);
        management.clients().setPermissionsEnabled(client, true);
        management.users().setPermissionsEnabled(true);
    }

    public static void invokeDelete(IAMShieldSession session)  {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        AdminPermissionManagement management = AdminPermissions.management(session, realm);
        List<Resource> byResourceServer = management.authz().getStoreFactory().getResourceStore().findByResourceServer(management.realmResourceServer());
        Assertions.assertEquals(5, byResourceServer.size());
        RoleModel removedRole = realm.getRole("removedRole");
        realm.removeRole(removedRole);
        ClientModel client = realm.getClientByClientId("removedClient");
        RoleModel removedClientRole = client.getRole("removedClientRole");
        client.removeRole(removedClientRole);
        GroupModel group = IAMShieldModelUtils.findGroupByPath(session, realm, "removedGroup");
        realm.removeGroup(group);
        byResourceServer = management.authz().getStoreFactory().getResourceStore().findByResourceServer(management.realmResourceServer());
        Assertions.assertEquals(2, byResourceServer.size());
        realm.removeClient(client.getId());
        byResourceServer = management.authz().getStoreFactory().getResourceStore().findByResourceServer(management.realmResourceServer());
        Assertions.assertEquals(1, byResourceServer.size());
        management.users().setPermissionsEnabled(false);
        Resource userResource = management.authz().getStoreFactory().getResourceStore().findByName(management.realmResourceServer(), "Users");
        Assertions.assertNull(userResource);
        byResourceServer = management.authz().getStoreFactory().getResourceStore().findByResourceServer(management.realmResourceServer());
        Assertions.assertEquals(0, byResourceServer.size());
    }
}
