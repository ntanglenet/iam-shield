package org.iamshield.tests.admin.userstorage;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.common.constants.KerberosConstants;
import org.iamshield.common.util.MultivaluedHashMap;
import org.iamshield.events.admin.OperationType;
import org.iamshield.events.admin.ResourceType;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.iamshield.representations.idm.ComponentRepresentation;
import org.iamshield.storage.UserStorageProvider;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.events.AdminEventAssertion;
import org.iamshield.tests.utils.admin.AdminEventPaths;

import java.util.List;

@IAMShieldIntegrationTest
public class UserStorageKerberosRestTest extends AbstractUserStorageRestTest {

    @Test
    public void testKerberosAuthenticatorEnabledAutomatically() {
        // Assert kerberos authenticator DISABLED
        AuthenticationExecutionInfoRepresentation kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.DISABLED.toString());

        // create LDAP provider with kerberos
        ComponentRepresentation ldapRep = createBasicLDAPProviderRep();
        ldapRep.getConfig().putSingle(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION, "true");

        String id = createComponent(ldapRep);

        // Assert kerberos authenticator ALTERNATIVE
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.ALTERNATIVE.toString());

        // Switch kerberos authenticator to DISABLED
        kerberosExecution.setRequirement(AuthenticationExecutionModel.Requirement.DISABLED.toString());
        managedRealm.admin().flows().updateExecutions("browser", kerberosExecution);
        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.UPDATE, AdminEventPaths.authUpdateExecutionPath("browser"), kerberosExecution, ResourceType.AUTH_EXECUTION);

        // update LDAP provider with kerberos (without changing kerberos switch)
        ldapRep = managedRealm.admin().components().component(id).toRepresentation();
        managedRealm.admin().components().component(id).update(ldapRep);
        adminEvents.clear();

        // Assert kerberos authenticator is still DISABLED
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.DISABLED.toString());

        // update LDAP provider with kerberos (with changing kerberos switch to disabled)
        ldapRep = managedRealm.admin().components().component(id).toRepresentation();
        ldapRep.getConfig().putSingle(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION, "false");
        managedRealm.admin().components().component(id).update(ldapRep);
        adminEvents.clear();

        // Assert kerberos authenticator is still DISABLED
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.DISABLED.toString());

        // update LDAP provider with kerberos (with changing kerberos switch to enabled)
        ldapRep = managedRealm.admin().components().component(id).toRepresentation();
        ldapRep.getConfig().putSingle(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION, "true");
        managedRealm.admin().components().component(id).update(ldapRep);
        adminEvents.clear();

        // Assert kerberos authenticator is still ALTERNATIVE
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.ALTERNATIVE.toString());

        // Cleanup
        kerberosExecution.setRequirement(AuthenticationExecutionModel.Requirement.DISABLED.toString());
        managedRealm.admin().flows().updateExecutions("browser", kerberosExecution);
        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.UPDATE, AdminEventPaths.authUpdateExecutionPath("browser"), kerberosExecution, ResourceType.AUTH_EXECUTION);
        removeComponent(id);
    }

    @Test
    public void testKerberosAuthenticatorChangedOnlyIfDisabled() {
        // Change kerberos to REQUIRED
        AuthenticationExecutionInfoRepresentation kerberosExecution = findKerberosExecution();
        kerberosExecution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED.toString());
        managedRealm.admin().flows().updateExecutions("browser", kerberosExecution);
        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.UPDATE, AdminEventPaths.authUpdateExecutionPath("browser"), kerberosExecution, ResourceType.AUTH_EXECUTION);

        // create LDAP provider with kerberos
        ComponentRepresentation ldapRep = createBasicLDAPProviderRep();
        ldapRep.getConfig().putSingle(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION, "true");

        String id = createComponent(ldapRep);


        // Assert kerberos authenticator still REQUIRED
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.REQUIRED.toString());

        // update LDAP provider with kerberos
        ldapRep = managedRealm.admin().components().component(id).toRepresentation();
        managedRealm.admin().components().component(id).update(ldapRep);
        adminEvents.clear();

        // Assert kerberos authenticator still REQUIRED
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.REQUIRED.toString());

        // Cleanup
        kerberosExecution.setRequirement(AuthenticationExecutionModel.Requirement.DISABLED.toString());
        managedRealm.admin().flows().updateExecutions("browser", kerberosExecution);
        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.UPDATE, AdminEventPaths.authUpdateExecutionPath("browser"), kerberosExecution, ResourceType.AUTH_EXECUTION);
        removeComponent(id);

    }


    // KEYCLOAK-4438
    @Test
    public void testKerberosAuthenticatorDisabledWhenProviderRemoved() {
        // Assert kerberos authenticator DISABLED
        AuthenticationExecutionInfoRepresentation kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.DISABLED.toString());

        // create LDAP provider with kerberos
        ComponentRepresentation ldapRep = createBasicLDAPProviderRep();
        ldapRep.getConfig().putSingle(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION, "true");


        String id = createComponent(ldapRep);

        // Assert kerberos authenticator ALTERNATIVE
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.ALTERNATIVE.toString());

        // Remove LDAP provider
        managedRealm.admin().components().component(id).remove();

        // Assert kerberos authenticator DISABLED
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.DISABLED.toString());

        // Add kerberos provider
        ComponentRepresentation kerberosRep = new ComponentRepresentation();
        kerberosRep.setName("kerberos");
        kerberosRep.setProviderId("kerberos");
        kerberosRep.setProviderType(UserStorageProvider.class.getName());
        kerberosRep.setConfig(new MultivaluedHashMap<>());
        kerberosRep.getConfig().putSingle("priority", Integer.toString(2));

        id = createComponent(kerberosRep);


        // Assert kerberos authenticator ALTERNATIVE
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.ALTERNATIVE.toString());

        // Switch kerberos authenticator to REQUIRED
        kerberosExecution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED.toString());
        managedRealm.admin().flows().updateExecutions("browser", kerberosExecution);

        // Remove Kerberos provider
        managedRealm.admin().components().component(id).remove();

        // Assert kerberos authenticator DISABLED
        kerberosExecution = findKerberosExecution();
        Assertions.assertEquals(kerberosExecution.getRequirement(), AuthenticationExecutionModel.Requirement.DISABLED.toString());
    }

    private AuthenticationExecutionInfoRepresentation findKerberosExecution() {
        AuthenticationExecutionInfoRepresentation kerberosExecution = null;
        List<AuthenticationExecutionInfoRepresentation> executionReps = managedRealm.admin().flows().getExecutions("browser");
        kerberosExecution = findExecutionByProvider("auth-spnego", executionReps);

        Assertions.assertNotNull(kerberosExecution);
        return kerberosExecution;
    }

    private static AuthenticationExecutionInfoRepresentation findExecutionByProvider(String provider, List<AuthenticationExecutionInfoRepresentation> executions) {
        for (AuthenticationExecutionInfoRepresentation exec : executions) {
            if (provider.equals(exec.getProviderId())) {
                return exec;
            }
        }
        return null;
    }
}
