package org.iamshield.tests.admin.partialimport;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.AuthorizationResource;
import org.iamshield.admin.client.resource.ClientResource;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.common.constants.ServiceAccountConstants;
import org.iamshield.partialimport.PartialImportResult;
import org.iamshield.partialimport.PartialImportResults;
import org.iamshield.partialimport.ResourceType;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.PartialImportRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.representations.idm.RolesRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.representations.idm.authorization.ResourceServerRepresentation;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.tests.utils.Assert;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@IAMShieldIntegrationTest(config = AbstractPartialImportTest.PartialImportServerConfig.class)
public class PartialImportClientTest extends AbstractPartialImportTest {

    @Test
    public void testAddClients() {
        setFail();
        addClients(false);

        PartialImportResults results = doImport();
        assertEquals(NUM_ENTITIES, results.getAdded());

        for (PartialImportResult result : results.getResults()) {
            String id = result.getId();
            ClientResource clientRsc = managedRealm.admin().clients().get(id);
            ClientRepresentation client = clientRsc.toRepresentation();
            assertTrue(client.getName().startsWith(CLIENT_PREFIX));
        }
    }

    @Test
    public void testAddClientsWithServiceAccountsAndAuthorization() {
        setFail();
        addClients(true);

        PartialImportResults results = doImport();
        assertEquals(NUM_ENTITIES * 2, results.getAdded());

        for (PartialImportResult result : results.getResults()) {
            if (result.getResourceType().equals(ResourceType.CLIENT)) {
                String id = result.getId();
                ClientResource clientRsc = managedRealm.admin().clients().get(id);
                ClientRepresentation client = clientRsc.toRepresentation();
                assertTrue(client.getName().startsWith(CLIENT_PREFIX));
                Assertions.assertTrue(client.isServiceAccountsEnabled());
                Assertions.assertTrue(client.getAuthorizationServicesEnabled());
                AuthorizationResource authRsc = clientRsc.authorization();
                ResourceServerRepresentation authRep = authRsc.exportSettings();
                Assertions.assertNotNull(authRep);
                Assertions.assertEquals(2, authRep.getResources().size());
                Assertions.assertEquals(3, authRep.getPolicies().size());
            } else {
                UserResource userRsc = managedRealm.admin().users().get(result.getId());
                Assert.assertTrue(userRsc.toRepresentation().getUsername().startsWith(
                        ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + CLIENT_PREFIX));
            }
        }
    }

    @Test
    public void testAddClientsFail() {
        addClients(false);
        testFail();
    }

    @Test
    public void testAddClientsSkip() {
        addClients(false);
        testSkip();
    }

    @Test
    public void testAddClientsSkipWithServiceAccountsAndAuthorization() {
        addClients(true);
        setSkip();
        PartialImportResults results = doImport();
        assertEquals(NUM_ENTITIES * 2, results.getAdded());

        results = doImport();
        assertEquals(NUM_ENTITIES * 2, results.getSkipped());
    }

    @Test
    public void testAddClientsOverwrite() {
        addClients(false);
        testOverwrite();
    }

    @Test
    public void testAddClientsOverwriteWithServiceAccountsAndAuthorization() {
        addClients(true);
        setOverwrite();
        PartialImportResults results = doImport();
        assertEquals(NUM_ENTITIES * 2, results.getAdded());

        results = doImport();
        assertEquals(NUM_ENTITIES * 2, results.getOverwritten());
    }

    @Test
    public void testAddClientsOverwriteServiceAccountsWithNoServiceAccounts() {
        addClients(true);
        setOverwrite();
        PartialImportResults results = doImport();
        assertEquals(NUM_ENTITIES * 2, results.getAdded());
        // check the service accounts are there
        for (int i = 0; i < NUM_ENTITIES; i++) {
            List<UserRepresentation> l = managedRealm.admin().users().search(ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + CLIENT_PREFIX + i);
            Assertions.assertEquals(1, l.size());
        }
        // re-import without service accounts enabled
        piRep = new PartialImportRepresentation();
        addClients(false);
        setOverwrite();
        results = doImport();
        assertEquals(NUM_ENTITIES, results.getOverwritten());
        // check the service accounts have been removed
        for (int i = 0; i < NUM_ENTITIES; i++) {
            List<UserRepresentation> l = managedRealm.admin().users().search(ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + CLIENT_PREFIX + i);
            Assertions.assertEquals(0, l.size());
        }
    }

    //KEYCLOAK-3042
    @Test
    public void testOverwriteExistingClientWithRoles() {
        setOverwrite();

        ClientRepresentation client = masterRealm.admin().clients().findByClientId("broker").get(0);
        List<RoleRepresentation> clientRoles = masterRealm.admin().clients().get(client.getId()).roles().list();

        Map<String, List<RoleRepresentation>> clients = new HashMap<>();
        clients.put(client.getClientId(), clientRoles);

        RolesRepresentation roles = new RolesRepresentation();
        roles.setClient(clients);

        piRep.setClients(List.of(client));
        piRep.setRoles(roles);

        doImport();
    }

    // KEYCLOAK-6058
    @Test
    public void testOverwriteExistingInternalClient() {
        setOverwrite();
        ClientRepresentation client = masterRealm.admin().clients().findByClientId("security-admin-console").get(0);
        ClientRepresentation client2 = masterRealm.admin().clients().findByClientId("master-realm").get(0);
        piRep.setClients(Arrays.asList(client, client2));

        PartialImportResults result = doImport();
        Assertions.assertEquals(0, result.getOverwritten());
    }

    @Test
    public void testOverwriteExistingClientWithServiceAccount() {
        setOverwrite();
        piRep.setClients(Collections.singletonList(serviceClient.admin().toRepresentation()));

        Assertions.assertEquals(1, doImport().getOverwritten());

        ClientRepresentation client = managedRealm.admin().clients().findByClientId(CLIENT_SERVICE_ACCOUNT).get(0);
        Assertions.assertDoesNotThrow(() -> managedRealm.admin().clients().get(client.getId()).getServiceAccountUser());
    }
}
