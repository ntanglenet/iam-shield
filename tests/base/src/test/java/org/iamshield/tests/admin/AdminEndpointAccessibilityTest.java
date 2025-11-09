package org.iamshield.tests.admin;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.admin.client.resource.RoleMappingResource;
import org.iamshield.models.AdminRoles;
import org.iamshield.models.Constants;
import org.iamshield.representations.idm.GroupRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testframework.admin.AdminClientFactory;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.InjectAdminClientFactory;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.GroupConfigBuilder;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.tests.utils.admin.ApiUtil;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;

@IAMShieldIntegrationTest
public class AdminEndpointAccessibilityTest {

    @InjectAdminClient
    IAMShield adminClient;

    @InjectAdminClientFactory
    AdminClientFactory adminClientFactory;

    /**
     * Verifies that the user does not have access to IAMShield Admin endpoint when role is not
     * assigned to that user.
     *
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void noAdminEndpointAccessWhenNoRoleAssigned() {
        String userName = "user-" + UUID.randomUUID();
        UserRepresentation user = UserConfigBuilder.create()
                .username(userName)
                .password("pwd")
                .build();
        final String realmName = "master";
        final String userUuid = ApiUtil.getCreatedId(adminClient.realm(realmName).users().create(user));

        IAMShield userClient = adminClientFactory.create().realm(realmName)
                .username(userName).password("pwd")
                .clientId(Constants.ADMIN_CLI_CLIENT_ID)
                .build();
        ClientErrorException e = Assertions.assertThrows(ClientErrorException.class,
                () -> userClient.realms().findAll()  // Any admin operation will do
        );
        assertThat(e.getMessage(), containsString(String.valueOf(Response.Status.FORBIDDEN.getStatusCode())));
        adminClient.realm(realmName).users().get(userUuid).remove();
    }

    /**
     * Verifies that the role assigned to a user is correctly handled by IAMShield Admin endpoint.
     *
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void adminEndpointAccessibleWhenAdminRoleAssignedToUser() {
        String userName = "user-" + UUID.randomUUID();
        UserRepresentation user = UserConfigBuilder.create()
                .username(userName)
                .password("pwd")
                .build();

        final String realmName = "master";
        RealmResource realm = adminClient.realms().realm(realmName);
        RoleRepresentation adminRole = realm.roles().get(AdminRoles.ADMIN).toRepresentation();
        assertThat(adminRole, notNullValue());
        assertThat(adminRole.getId(), notNullValue());

        final String userUuid = ApiUtil.getCreatedId(adminClient.realm(realmName).users().create(user));
        assertThat(userUuid, notNullValue());

        RoleMappingResource mappings = realm.users().get(userUuid).roles();
        mappings.realmLevel().add(List.of(adminRole));

        IAMShield userClient = adminClientFactory.create().realm(realmName)
                .username(userName).password("pwd")
                .clientId(Constants.ADMIN_CLI_CLIENT_ID)
                .build();

        assertFalse(userClient.realms().findAll().isEmpty()); // Any admin operation will do
        adminClient.realm(realmName).users().get(userUuid).remove();
    }

    /**
     * Verifies that the role assigned to a user's group is correctly handled by IAMShield Admin endpoint.
     *
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void adminEndpointAccessibleWhenAdminRoleAssignedToGroup() {
        String userName = "user-" + UUID.randomUUID();
        String groupName = "group-" + UUID.randomUUID();

        final String realmName = "master";
        RealmResource realm = adminClient.realms().realm(realmName);
        RoleRepresentation adminRole = realm.roles().get(AdminRoles.ADMIN).toRepresentation();
        assertThat(adminRole, notNullValue());
        assertThat(adminRole.getId(), notNullValue());

        UserRepresentation user = UserConfigBuilder.create()
                .username(userName)
                .password("pwd")
                .build();
        final String userUuid = ApiUtil.getCreatedId(adminClient.realm(realmName).users().create(user));
        assertThat(userUuid, notNullValue());

        GroupRepresentation group = GroupConfigBuilder.create().name(groupName).build();
        Response response = realm.groups().add(group);
        String groupId = ApiUtil.getCreatedId(response);

        RoleMappingResource mappings = realm.groups().group(groupId).roles();
        mappings.realmLevel().add(List.of(adminRole));

        realm.users().get(userUuid).joinGroup(groupId);

        IAMShield userClient = adminClientFactory.create().realm(realmName)
                .username(userName).password("pwd")
                .clientId(Constants.ADMIN_CLI_CLIENT_ID)
                .build();
        assertFalse(userClient.realms().findAll().isEmpty()); // Any admin operation will do

        adminClient.realm(realmName).groups().group(groupId).remove();
        adminClient.realm(realmName).users().get(userUuid).remove();
    }

    /**
     * Verifies that the role assigned to a user's group is correctly handled by IAMShield Admin endpoint.
     *
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void adminEndpointAccessibleWhenAdminRoleAssignedToGroupAfterUserJoinedIt() {
        String userName = "user-" + UUID.randomUUID();
        String groupName = "group-" + UUID.randomUUID();
        final String realmName = "master";

        RealmResource realm = adminClient.realms().realm(realmName);
        RoleRepresentation adminRole = realm.roles().get(AdminRoles.ADMIN).toRepresentation();
        assertThat(adminRole, notNullValue());
        assertThat(adminRole.getId(), notNullValue());

        UserRepresentation user = UserConfigBuilder.create()
                .username(userName)
                .password("pwd")
                .build();
        final String userUuid = ApiUtil.getCreatedId(adminClient.realm(realmName).users().create(user));
        assertThat(userUuid, notNullValue());

        GroupRepresentation group = GroupConfigBuilder.create().name(groupName).build();
        Response response = realm.groups().add(group);
        String groupId = ApiUtil.getCreatedId(response);

        realm.users().get(userUuid).joinGroup(groupId);

        RoleMappingResource mappings = realm.groups().group(groupId).roles();

        mappings.realmLevel().add(List.of(adminRole));

        IAMShield userClient = adminClientFactory.create().realm(realmName)
                .username(userName).password("pwd")
                .clientId(Constants.ADMIN_CLI_CLIENT_ID)
                .build();
        assertFalse(userClient.realms().findAll().isEmpty()); // Any admin operation will do

        adminClient.realm(realmName).groups().group(groupId).remove();
        adminClient.realm(realmName).users().get(userUuid).remove();
    }

}
