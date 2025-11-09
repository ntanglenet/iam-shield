package org.iamshield.tests.admin.user;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.IdentityProviderResource;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.common.util.MultivaluedHashMap;
import org.iamshield.events.admin.OperationType;
import org.iamshield.events.admin.ResourceType;
import org.iamshield.models.credential.PasswordCredentialModel;
import org.iamshield.models.utils.ModelToRepresentation;
import org.iamshield.representations.idm.ComponentRepresentation;
import org.iamshield.representations.idm.CredentialRepresentation;
import org.iamshield.representations.idm.FederatedIdentityRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.storage.StorageId;
import org.iamshield.storage.UserStorageProvider;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.events.AdminEventAssertion;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.tests.utils.Assert;
import org.iamshield.tests.utils.admin.AdminEventPaths;
import org.iamshield.tests.utils.admin.ApiUtil;
import org.iamshield.testsuite.federation.UserMapStorageFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.iamshield.storage.UserStorageProviderModel.IMPORT_ENABLED;

@IAMShieldIntegrationTest(config = UserFedarationTest.UserFederationServerConfig.class)
public class UserFedarationTest extends AbstractUserTest {

    @Test
    public void getFederatedIdentities() {
        // Add sample identity provider
        addSampleIdentityProvider();

        // Add sample user
        String id = createUser();
        UserResource user = managedRealm.admin().users().get(id);
        assertEquals(0, user.getFederatedIdentity().size());

        // Add social link to the user
        FederatedIdentityRepresentation link = new FederatedIdentityRepresentation();
        link.setUserId("social-user-id");
        link.setUserName("social-username");
        addFederatedIdentity(id, "social-provider-id", link);

        // Verify social link is here
        List<FederatedIdentityRepresentation> federatedIdentities = user.getFederatedIdentity();
        assertEquals(1, federatedIdentities.size());
        link = federatedIdentities.get(0);
        assertEquals("social-provider-id", link.getIdentityProvider());
        assertEquals("social-user-id", link.getUserId());
        assertEquals("social-username", link.getUserName());

        // Remove social link now
        user.removeFederatedIdentity("social-provider-id");
        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.DELETE, AdminEventPaths.userFederatedIdentityLink(id, "social-provider-id"), ResourceType.USER);
        assertEquals(0, user.getFederatedIdentity().size());

        removeSampleIdentityProvider();
    }

    @Test
    public void testUpdateCredentialLabelForFederatedUser() {
        // Create user federation
        ComponentRepresentation memProvider = new ComponentRepresentation();
        memProvider.setName("memory");
        memProvider.setProviderId(UserMapStorageFactory.PROVIDER_ID);
        memProvider.setProviderType(UserStorageProvider.class.getName());
        memProvider.setConfig(new MultivaluedHashMap<>());
        memProvider.getConfig().putSingle("priority", Integer.toString(0));
        memProvider.getConfig().putSingle(IMPORT_ENABLED, Boolean.toString(false));

        String memProviderId = ApiUtil.getCreatedId(managedRealm.admin().components().add(memProvider));
        managedRealm.cleanup().add(realm -> realm.components().component(memProviderId).remove());

        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.CREATE, AdminEventPaths.componentPath(memProviderId), memProvider, ResourceType.COMPONENT);

        // Create federated user
        String username = "fed-user1";
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setUsername(username);
        userRepresentation.setEmail("feduser1@mail.com");
        userRepresentation.setRequiredActions(Collections.emptyList());
        userRepresentation.setEnabled(true);
        userRepresentation.setFederationLink(memProviderId);

        PasswordCredentialModel pcm = PasswordCredentialModel.createFromValues("my-algorithm", "theSalt".getBytes(), 22, "ABC");
        CredentialRepresentation hashedPassword = ModelToRepresentation.toRepresentation(pcm);
        hashedPassword.setCreatedDate(1001L);
        hashedPassword.setUserLabel("label");
        hashedPassword.setType(CredentialRepresentation.PASSWORD);

        userRepresentation.setCredentials(Arrays.asList(hashedPassword));
        String userId = ApiUtil.getCreatedId(managedRealm.admin().users().create(userRepresentation));
        Assert.assertFalse(StorageId.isLocalStorage(userId));

        UserResource user = ApiUtil.findUserByUsernameId(managedRealm.admin(), username);
        List<CredentialRepresentation> credentials = user.credentials();
        Assertions.assertNotNull(credentials);
        Assertions.assertEquals(1, credentials.size());
        Assertions.assertEquals("label", credentials.get(0).getUserLabel());

        // Update federated credential user label
        user.setCredentialUserLabel(credentials.get(0).getId(), "updatedLabel");
        credentials = user.credentials();
        Assertions.assertNotNull(credentials);
        Assertions.assertEquals(1, credentials.size());
        Assertions.assertEquals("updatedLabel", credentials.get(0).getUserLabel());
    }

    @Test
    public void createFederatedIdentities() {
        String identityProviderAlias = "social-provider-id";
        String username = "federated-identities";
        String federatedUserId = "federated-user-id";

        addSampleIdentityProvider();

        UserRepresentation build = UserConfigBuilder.create()
                .username(username)
                .federatedLink(identityProviderAlias, federatedUserId, username)
                .build();

        //when
        String userId = createUser(build, false);
        List<FederatedIdentityRepresentation> obtainedFederatedIdentities = managedRealm.admin().users().get(userId).getFederatedIdentity();

        //then
        assertEquals(1, obtainedFederatedIdentities.size());
        assertEquals(federatedUserId, obtainedFederatedIdentities.get(0).getUserId());
        assertEquals(username, obtainedFederatedIdentities.get(0).getUserName());
        assertEquals(identityProviderAlias, obtainedFederatedIdentities.get(0).getIdentityProvider());
    }

    private void removeSampleIdentityProvider() {
        IdentityProviderResource resource = managedRealm.admin().identityProviders().get("social-provider-id");
        Assertions.assertNotNull(resource);
        resource.remove();
        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.DELETE, AdminEventPaths.identityProviderPath("social-provider-id"), ResourceType.IDENTITY_PROVIDER);
    }

    public static class UserFederationServerConfig implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            return config.dependency("org.iamshield.tests", "keycloak-tests-custom-providers");
        }
    }
}
