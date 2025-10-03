package org.iamshield.tests.db;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.config.DatabaseOptions;
import org.iamshield.quarkus.runtime.configuration.Configuration;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;

@IAMShieldIntegrationTest
public class DbTest {

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @Test
    public void ensurePostgreSQLSettingsAreApplied() {
        runOnServer.run(session -> {
            if (Configuration.getConfigValue(DatabaseOptions.DB).getValue().equals("postgres") &&
                Configuration.getConfigValue(DatabaseOptions.DB_DRIVER).getValue().equals("org.postgresql.Driver")) {
                Assertions.assertEquals("primary", Configuration.getConfigValue(DatabaseOptions.DB_POSTGRESQL_TARGET_SERVER_TYPE).getValue());
            } else {
                Assertions.assertNull(Configuration.getConfigValue(DatabaseOptions.DB_POSTGRESQL_TARGET_SERVER_TYPE).getValue());
            }
        });
    }

}
