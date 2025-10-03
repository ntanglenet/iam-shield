package org.iamshield.tests.clustering;

import org.junit.jupiter.api.Test;
import org.iamshield.testframework.annotations.InjectTestDatabase;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.database.TestDatabase;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.tests.db.CaseSensitiveSchemaTest;

@IAMShieldIntegrationTest(config = CaseSensitiveSchemaTest.CaseSensitiveServerConfig.class)
public class JdbcPingCustomSchemaTest {
    @InjectTestDatabase(config = CaseSensitiveSchemaTest.CaseSensitiveDatabaseConfig.class, lifecycle = LifeCycle.CLASS)
    TestDatabase db;

    @Test
    public void testClusterFormed() {
        // no-op ClusteredKeycloakServer will fail if a cluster is not formed
    }
}
