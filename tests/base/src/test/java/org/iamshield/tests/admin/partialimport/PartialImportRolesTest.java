package org.iamshield.tests.admin.partialimport;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.RoleResource;
import org.iamshield.partialimport.PartialImportResult;
import org.iamshield.partialimport.PartialImportResults;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.representations.idm.RolesRepresentation;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@IAMShieldIntegrationTest(config = AbstractPartialImportTest.PartialImportServerConfig.class)
public class PartialImportRolesTest extends AbstractPartialImportTest {

    @Test
    public void testAddRealmRoles() {
        setFail();
        addRealmRoles();

        PartialImportResults results = doImport();
        assertEquals(NUM_ENTITIES, results.getAdded());

        for (PartialImportResult result : results.getResults()) {
            String name = result.getResourceName();
            RoleResource roleRsc = managedRealm.admin().roles().get(name);
            RoleRepresentation role = roleRsc.toRepresentation();
            assertTrue(role.getName().startsWith(REALM_ROLE_PREFIX));
        }
    }

    @Test
    public void testAddClientRoles() {
        setFail();
        addClientRoles();

        PartialImportResults results = doImport();
        assertEquals(NUM_ENTITIES, results.getAdded());

        List<RoleRepresentation> clientRoles = rolesClient.admin().roles().list();
        assertEquals(NUM_ENTITIES, clientRoles.size());

        for (RoleRepresentation roleRep : clientRoles) {
            assertTrue(roleRep.getName().startsWith(CLIENT_ROLE_PREFIX));
        }
    }

    @Test
    public void testAddRealmRolesFail() {
        addRealmRoles();
        testFail();
    }

    @Test
    public void testAddClientRolesFail() {
        addClientRoles();
        testFail();
    }

    @Test
    public void testAddRealmRolesSkip() {
        addRealmRoles();
        testSkip();
    }

    @Test
    public void testAddClientRolesSkip() {
        addClientRoles();
        testSkip();
    }

    @Test
    public void testAddRealmRolesOverwrite() {
        addRealmRoles();
        testOverwrite();
    }

    @Test
    public void testAddClientRolesOverwrite() {
        addClientRoles();
        testOverwrite();
    }

    @Test
    public void testOverwriteDefaultRole() {
        setOverwrite();

        RolesRepresentation roles = new RolesRepresentation();
        RoleRepresentation oldDefaultRole = managedRealm.admin().toRepresentation().getDefaultRole();
        roles.setRealm(Collections.singletonList(oldDefaultRole));
        piRep.setRoles(roles);

        Assertions.assertEquals(1, doImport().getOverwritten(), "default role should have been overwritten");
    }
}
