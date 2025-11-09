package org.iamshield.tests.admin.client;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Assertions;
import org.iamshield.admin.client.resource.ClientScopesResource;
import org.iamshield.events.admin.OperationType;
import org.iamshield.events.admin.ResourceType;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.ClientScopeRepresentation;
import org.iamshield.testframework.annotations.InjectAdminEvents;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.events.AdminEventAssertion;
import org.iamshield.testframework.events.AdminEvents;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.tests.utils.admin.AdminEventPaths;
import org.iamshield.tests.utils.admin.ApiUtil;
import org.iamshield.util.JsonSerialization;

import java.io.IOException;
import java.util.Map;

@IAMShieldIntegrationTest
public class AbstractClientScopeTest {

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectAdminEvents
    AdminEvents adminEvents;

    void handleExpectedCreateFailure(ClientScopeRepresentation scopeRep, int expectedErrorCode, String expectedErrorMessage) {
        try (Response resp = clientScopes().create(scopeRep)) {
            Assertions.assertEquals(expectedErrorCode, resp.getStatus());
            String respBody = resp.readEntity(String.class);
            Map<String, String> responseJson;
            try {
                responseJson = JsonSerialization.readValue(respBody, Map.class);
                Assertions.assertEquals(expectedErrorMessage, responseJson.get("errorMessage"));
            } catch (IOException e) {
                Assertions.fail("Failed to extract the errorMessage from a CreateScope Response");
            }
        }
    }

    ClientScopesResource clientScopes() {
        return managedRealm.admin().clientScopes();
    }

    String createClientScope(ClientScopeRepresentation clientScopeRep) {
        Response resp = clientScopes().create(clientScopeRep);
        final String clientScopeId = ApiUtil.getCreatedId(resp);

        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.CREATE, AdminEventPaths.clientScopeResourcePath(clientScopeId), clientScopeRep, ResourceType.CLIENT_SCOPE);

        return clientScopeId;
    }

    String createClientScopeWithCleanup(ClientScopeRepresentation clientScopeRep) {
        String clientScopeId = createClientScope(clientScopeRep);
        managedRealm.cleanup().add(r -> r.clientScopes().get(clientScopeId).remove());
        return clientScopeId;
    }

    String createClientWithCleanup(ClientRepresentation clientRep) {
        Response resp = managedRealm.admin().clients().create(clientRep);
        final String clientUuid = ApiUtil.getCreatedId(resp);
        managedRealm.cleanup().add(r -> r.clients().get(clientUuid).remove());

        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.CREATE, AdminEventPaths.clientResourcePath(clientUuid), clientRep, ResourceType.CLIENT);
        return clientUuid;
    }

}
