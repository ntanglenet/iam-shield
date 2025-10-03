package org.iamshield.tests.db;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.RolesResource;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.testframework.annotations.InjectClient;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.database.TestDatabase;
import org.iamshield.testframework.injection.Extensions;
import org.iamshield.testframework.realm.ManagedClient;
import org.iamshield.testframework.realm.RoleConfigBuilder;

@IAMShieldIntegrationTest
public abstract class AbstractDBSchemaTest {

    @InjectClient
    ManagedClient managedClient;

    protected static String dbType() {
        return Extensions.getInstance().findSupplierByType(TestDatabase.class).getAlias();
    }

    @Test
    public void testCaseSensitiveSchema() {
        RoleRepresentation role1 = RoleConfigBuilder.create()
                .name("role1")
                .description("role1-description")
                .singleAttribute("role1-attr-key", "role1-attr-val")
                .build();
        RolesResource roles = managedClient.admin().roles();
        roles.create(role1);
        roles.deleteRole(role1.getName());
    }
}
