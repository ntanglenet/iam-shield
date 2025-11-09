package org.iamshield.tests.admin.realm;

import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.RoleResource;
import org.iamshield.representations.idm.GroupRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

@IAMShieldIntegrationTest
public class RealmRolesGroupTest extends AbstractRealmRolesTest {

    /**
     * KEYCLOAK-4978 Verifies that Groups assigned to Role are being properly retrieved as members in API endpoint for role membership
     */
    @Test
    public void testGroupsInRole() {
        RoleResource role = managedRealm.admin().roles().get("role-with-users");

        List<GroupRepresentation> groups = managedRealm.admin().groups().groups();
        GroupRepresentation groupRep = groups.stream().filter(g -> g.getPath().equals("/test-role-group")).findFirst().get();

        RoleResource roleResource = managedRealm.admin().roles().get(role.toRepresentation().getName());
        List<RoleRepresentation> rolesToAdd = new LinkedList<>();
        rolesToAdd.add(roleResource.toRepresentation());
        managedRealm.admin().groups().group(groupRep.getId()).roles().realmLevel().add(rolesToAdd);

        roleResource = managedRealm.admin().roles().get(role.toRepresentation().getName());

        Set<GroupRepresentation> groupsInRole = roleResource.getRoleGroupMembers();
        assertTrue(groupsInRole.stream().anyMatch(g -> g.getPath().equals("/test-role-group")));
    }

    /**
     * KEYCLOAK-4978  Verifies that Role with no users assigned is being properly retrieved without groups in API endpoint for role membership
     */
    @Test
    public void testGroupsNotInRole() {
        RoleResource role = managedRealm.admin().roles().get("role-without-users");

        role = managedRealm.admin().roles().get(role.toRepresentation().getName());

        Set<GroupRepresentation> groupsInRole = role.getRoleGroupMembers();
        assertTrue(groupsInRole.isEmpty());
    }
}
