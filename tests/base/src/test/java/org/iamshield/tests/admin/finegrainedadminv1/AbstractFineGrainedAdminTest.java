package org.iamshield.tests.admin.finegrainedadminv1;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.client.cli.util.ConfigUtil;
import org.iamshield.common.Profile;
import org.iamshield.models.AdminRoles;
import org.iamshield.models.ClientModel;
import org.iamshield.models.GroupModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserCredentialModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.representations.idm.authorization.ClientPolicyRepresentation;
import org.iamshield.representations.idm.authorization.DecisionStrategy;
import org.iamshield.representations.idm.authorization.Logic;
import org.iamshield.representations.idm.authorization.UserPolicyRepresentation;
import org.iamshield.services.resources.admin.fgap.AdminPermissionManagement;
import org.iamshield.services.resources.admin.fgap.AdminPermissions;
import org.iamshield.testframework.admin.AdminClientFactory;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.InjectAdminClientFactory;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

public class AbstractFineGrainedAdminTest {

    @InjectRealm(lifecycle = LifeCycle.METHOD)
    ManagedRealm managedRealm;

    @InjectRealm(ref = "master", attachTo = "master")
    ManagedRealm masterRealm;

    @InjectAdminClientFactory
    AdminClientFactory adminClientFactory;

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @InjectAdminClient
    IAMShield adminClient;

    @InjectOAuthClient
    OAuthClient oauth;

    private static final Logger LOGGER = Logger.getLogger(FineGrainedAdminWithTokenExchangeTest.class);

    public static final String REALM_NAME = "default";
    public static final String CLIENT_NAME = "application";

    public static void setupPolices(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        AdminPermissionManagement permissions = AdminPermissions.management(session, realm);
        RoleModel realmRole = realm.addRole("realm-role");
        RoleModel realmRole2 = realm.addRole("realm-role2");
        ClientModel client1 = realm.addClient(CLIENT_NAME);
        realm.addClientScope("scope");
        client1.setFullScopeAllowed(false);
        RoleModel client1Role = client1.addRole("client-role");
        GroupModel group = realm.createGroup("top");

        RoleModel mapperRole = realm.addRole("mapper");
        RoleModel managerRole = realm.addRole("manager");
        RoleModel compositeRole = realm.addRole("composite-role");
        compositeRole.addCompositeRole(mapperRole);
        compositeRole.addCompositeRole(managerRole);

        // realm-role and application.client-role will have a role policy associated with their map-role permission
        {
            permissions.roles().setPermissionsEnabled(client1Role, true);
            Policy mapRolePermission = permissions.roles().mapRolePermission(client1Role);
            ResourceServer server = permissions.roles().resourceServer(client1Role);
            Policy mapperPolicy = permissions.roles().rolePolicy(server, mapperRole);
            mapRolePermission.addAssociatedPolicy(mapperPolicy);
        }

        {
            permissions.roles().setPermissionsEnabled(realmRole, true);
            Policy mapRolePermission = permissions.roles().mapRolePermission(realmRole);
            ResourceServer server = permissions.roles().resourceServer(realmRole);
            Policy mapperPolicy = permissions.roles().rolePolicy(server, mapperRole);
            mapRolePermission.addAssociatedPolicy(mapperPolicy);
        }

        // realmRole2 will have an empty map-role policy
        {
            permissions.roles().setPermissionsEnabled(realmRole2, true);
        }

        // setup Users manage policies
        {
            permissions.users().setPermissionsEnabled(true);
            ResourceServer server = permissions.realmResourceServer();
            Policy managerPolicy = permissions.roles().rolePolicy(server, managerRole);
            Policy permission = permissions.users().managePermission();
            permission.addAssociatedPolicy(managerPolicy);
            permission.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
        }
        {
            permissions.groups().setPermissionsEnabled(group, true);
        }
        {
            permissions.clients().setPermissionsEnabled(client1, true);
        }
        // setup Users impersonate policy
        {
            ClientModel realmManagementClient = realm.getClientByClientId("realm-management");
            RoleModel adminRole = realmManagementClient.getRole(AdminRoles.REALM_ADMIN);
            permissions.users().setPermissionsEnabled(true);
            ResourceServer server = permissions.realmResourceServer();
            Policy adminPolicy = permissions.roles().rolePolicy(server, adminRole);
            adminPolicy.setLogic(Logic.NEGATIVE);
            Policy permission = permissions.users().userImpersonatedPermission();
            permission.addAssociatedPolicy(adminPolicy);
            permission.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        }
    }

    public static void setupUsers(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        ClientModel client = realm.getClientByClientId(CLIENT_NAME);
        RoleModel realmRole = realm.getRole("realm-role");
        RoleModel realmRole2 = realm.getRole("realm-role2");
        RoleModel clientRole = client.getRole("client-role");
        RoleModel mapperRole = realm.getRole("mapper");
        RoleModel managerRole = realm.getRole("manager");
        RoleModel compositeRole = realm.getRole("composite-role");
        ClientModel realmManagementClient = realm.getClientByClientId("realm-management");
        RoleModel adminRole = realmManagementClient.getRole(AdminRoles.REALM_ADMIN);
        RoleModel queryGroupsRole = realmManagementClient.getRole(AdminRoles.QUERY_GROUPS);
        RoleModel queryUsersRole = realmManagementClient.getRole(AdminRoles.QUERY_USERS);
        RoleModel queryClientsRole = realmManagementClient.getRole(AdminRoles.QUERY_CLIENTS);

        UserModel nomapAdmin = session.users().addUser(realm, "nomap-admin");
        nomapAdmin.setFirstName("No Map");
        nomapAdmin.setLastName("Admin");
        nomapAdmin.setEmail("nomap@admin");
        nomapAdmin.setEnabled(true);
        nomapAdmin.credentialManager().updateCredential(UserCredentialModel.password("password"));
        nomapAdmin.grantRole(adminRole);

        UserModel anotherAdmin = session.users().addUser(realm, "anotherAdmin");
        anotherAdmin.setFirstName("Another");
        anotherAdmin.setLastName("Admin");
        anotherAdmin.setEmail("another@admin");
        anotherAdmin.setEnabled(true);
        anotherAdmin.credentialManager().updateCredential(UserCredentialModel.password("password"));
        anotherAdmin.grantRole(adminRole);

        UserModel authorizedUser = session.users().addUser(realm, "authorized");
        authorizedUser.setFirstName("Authorized");
        authorizedUser.setLastName("User");
        authorizedUser.setEmail("authorized@user");
        authorizedUser.setEnabled(true);
        authorizedUser.credentialManager().updateCredential(UserCredentialModel.password("password"));
        authorizedUser.grantRole(mapperRole);
        authorizedUser.grantRole(managerRole);

        UserModel authorizedComposite = session.users().addUser(realm, "authorizedComposite");
        authorizedComposite.setFirstName("Authorized");
        authorizedComposite.setLastName("Composite");
        authorizedComposite.setEmail("authorized@Composite");
        authorizedComposite.setEnabled(true);
        authorizedComposite.credentialManager().updateCredential(UserCredentialModel.password("password"));
        authorizedComposite.grantRole(compositeRole);

        UserModel unauthorizedUser = session.users().addUser(realm, "unauthorized");
        unauthorizedUser.setFirstName("Unauthorized");
        unauthorizedUser.setLastName("User");
        unauthorizedUser.setEmail("unauthorized@user");
        unauthorizedUser.setEnabled(true);
        unauthorizedUser.credentialManager().updateCredential(UserCredentialModel.password("password"));

        UserModel unauthorizedMapper = session.users().addUser(realm, "unauthorizedMapper");
        unauthorizedMapper.setFirstName("Unauthorized");
        unauthorizedMapper.setLastName("Mapper");
        unauthorizedMapper.setEmail("unauthorized@Mapper");
        unauthorizedMapper.setEnabled(true);
        unauthorizedMapper.credentialManager().updateCredential(UserCredentialModel.password("password"));
        unauthorizedMapper.grantRole(managerRole);

        UserModel user1 = session.users().addUser(realm, "user1");
        user1.setFirstName("User");
        user1.setLastName("One");
        user1.setEmail("user@one");
        user1.setEnabled(true);

        // group management
        AdminPermissionManagement permissions = AdminPermissions.management(session, realm);

        GroupModel group =  IAMShieldModelUtils.findGroupByPath(session, realm, "top");
        UserModel groupMember = session.users().addUser(realm, "groupMember");
        groupMember.setFirstName("Group");
        groupMember.setLastName("Member");
        groupMember.setEmail("group@member");
        groupMember.joinGroup(group);
        groupMember.setEnabled(true);
        UserModel groupManager = session.users().addUser(realm, "groupManager");
        groupManager.setFirstName("Group");
        groupManager.setLastName("Manager");
        groupManager.setEmail("group@manager");
        groupManager.grantRole(queryGroupsRole);
        groupManager.grantRole(queryUsersRole);
        groupManager.setEnabled(true);
        groupManager.grantRole(mapperRole);
        groupManager.credentialManager().updateCredential(UserCredentialModel.password("password"));

        UserModel groupManagerNoMapper = session.users().addUser(realm, "noMapperGroupManager");
        groupManagerNoMapper.setFirstName("No Mapper");
        groupManagerNoMapper.setLastName("Group Manager");
        groupManagerNoMapper.setEmail("nomapper@groupmanager");
        groupManagerNoMapper.setEnabled(true);
        groupManagerNoMapper.credentialManager().updateCredential(UserCredentialModel.password("password"));
        groupManagerNoMapper.grantRole(queryGroupsRole);
        groupManagerNoMapper.grantRole(queryUsersRole);

        UserPolicyRepresentation groupManagerRep = new UserPolicyRepresentation();
        groupManagerRep.setName("groupManagers");
        groupManagerRep.addUser("groupManager");
        groupManagerRep.addUser("noMapperGroupManager");
        ResourceServer server = permissions.realmResourceServer();
        Policy groupManagerPolicy = permissions.authz().getStoreFactory().getPolicyStore().create(server, groupManagerRep);
        permissions.groups().manageMembersPermission(group).addAssociatedPolicy(groupManagerPolicy);
        permissions.groups().manageMembershipPermission(group).addAssociatedPolicy(groupManagerPolicy);
        permissions.groups().viewPermission(group).addAssociatedPolicy(groupManagerPolicy);

        UserModel clientMapper = session.users().addUser(realm, "clientMapper");
        clientMapper.setFirstName("Client");
        clientMapper.setLastName("Mapper");
        clientMapper.setEmail("client@mapper");
        clientMapper.setEnabled(true);
        clientMapper.grantRole(managerRole);
        clientMapper.grantRole(queryUsersRole);
        clientMapper.credentialManager().updateCredential(UserCredentialModel.password("password"));
        Policy clientMapperPolicy = permissions.clients().mapRolesPermission(client);
        UserPolicyRepresentation userRep = new UserPolicyRepresentation();
        userRep.setName("userClientMapper");
        userRep.addUser("clientMapper");
        Policy userPolicy = permissions.authz().getStoreFactory().getPolicyStore().create(permissions.clients().resourceServer(client), userRep);
        clientMapperPolicy.addAssociatedPolicy(userPolicy);

        UserModel clientManager = session.users().addUser(realm, "clientManager");
        clientManager.setFirstName("Client");
        clientManager.setLastName("Manager");
        clientManager.setEmail("client@manager");
        clientManager.setEnabled(true);
        clientManager.grantRole(queryClientsRole);
        clientManager.credentialManager().updateCredential(UserCredentialModel.password("password"));

        Policy clientManagerPolicy = permissions.clients().managePermission(client);
        userRep = new UserPolicyRepresentation();
        userRep.setName("clientManager");
        userRep.addUser("clientManager");
        userPolicy = permissions.authz().getStoreFactory().getPolicyStore().create(permissions.clients().resourceServer(client), userRep);
        clientManagerPolicy.addAssociatedPolicy(userPolicy);


        UserModel clientConfigurer = session.users().addUser(realm, "clientConfigurer");
        clientConfigurer.setFirstName("Client");
        clientConfigurer.setLastName("Configurer");
        clientConfigurer.setEmail("client@configurer");
        clientConfigurer.setEnabled(true);
        clientConfigurer.grantRole(queryClientsRole);
        clientConfigurer.credentialManager().updateCredential(UserCredentialModel.password("password"));

        Policy clientConfigurePolicy = permissions.clients().configurePermission(client);
        userRep = new UserPolicyRepresentation();
        userRep.setName("clientConfigure");
        userRep.addUser("clientConfigurer");
        userPolicy = permissions.authz().getStoreFactory().getPolicyStore().create(permissions.clients().resourceServer(client), userRep);
        clientConfigurePolicy.addAssociatedPolicy(userPolicy);


        UserModel groupViewer = session.users().addUser(realm, "groupViewer");
        groupViewer.setFirstName("Group");
        groupViewer.setLastName("Viewer");
        groupViewer.setEmail("group@viewer");
        groupViewer.grantRole(queryGroupsRole);
        groupViewer.grantRole(queryUsersRole);
        groupViewer.setEnabled(true);
        groupViewer.credentialManager().updateCredential(UserCredentialModel.password("password"));

        UserPolicyRepresentation groupViewMembersRep = new UserPolicyRepresentation();
        groupViewMembersRep.setName("groupMemberViewers");
        groupViewMembersRep.addUser("groupViewer");
        Policy groupViewMembersPolicy = permissions.authz().getStoreFactory().getPolicyStore().create(server, groupViewMembersRep);
        Policy groupViewMembersPermission = permissions.groups().viewMembersPermission(group);
        groupViewMembersPermission.addAssociatedPolicy(groupViewMembersPolicy);
    }

    protected String checkTokenExchange(boolean shouldPass) {
        runOnServer.run(AbstractFineGrainedAdminTest::setupTokenExchange);
        oauth.realm("master");
        oauth.client("tokenexclient", "password");
        String exchanged = null;
        String token = oauth.doPasswordGrantRequest("admin", "admin").getAccessToken();
        Assertions.assertNotNull(token);
        try {
            exchanged = oauth.tokenExchangeRequest(token).audience("admin-cli").send().getAccessToken();
        } catch (AssertionError e) {
            LOGGER.info("Error message is expected from oauth: " + e.getMessage());
        }
        if (shouldPass)
            Assertions.assertNotNull(exchanged);
        else
            Assertions.assertNull(exchanged);
        return exchanged;
    }

    private static void setupTokenExchange(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName("master");
        ClientModel client = session.clients().getClientByClientId(realm, "tokenexclient");
        if (client != null) {
            return;
        }

        ClientModel tokenexclient = realm.addClient("tokenexclient");
        tokenexclient.setEnabled(true);
        tokenexclient.addRedirectUri("http://localhost:*");
        tokenexclient.setPublicClient(false);
        tokenexclient.setSecret("password");
        tokenexclient.setDirectAccessGrantsEnabled(true);

        // permission for client to client exchange to "target" client
        ClientModel adminCli = realm.getClientByClientId(ConfigUtil.DEFAULT_CLIENT);
        AdminPermissionManagement management = AdminPermissions.management(session, realm);
        management.clients().setPermissionsEnabled(adminCli, true);
        ClientPolicyRepresentation clientRep = new ClientPolicyRepresentation();
        clientRep.setName("to");
        clientRep.addClient(tokenexclient.getId());
        ResourceServer server = management.realmResourceServer();
        Policy clientPolicy = management.authz().getStoreFactory().getPolicyStore().create(server, clientRep);
        management.clients().exchangeToPermission(adminCli).addAssociatedPolicy(clientPolicy);
    }

    public static class FineGrainedAdminServerConf implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            config.features(Profile.Feature.ADMIN_FINE_GRAINED_AUTHZ);

            return config;
        }
    }
}
