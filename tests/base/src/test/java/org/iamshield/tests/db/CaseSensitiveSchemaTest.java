package org.iamshield.tests.db;

import org.iamshield.testframework.annotations.InjectTestDatabase;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.conditions.DisabledForDatabases;
import org.iamshield.testframework.database.DatabaseConfig;
import org.iamshield.testframework.database.DatabaseConfigBuilder;
import org.iamshield.testframework.database.PostgresTestDatabase;
import org.iamshield.testframework.database.TestDatabase;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

@IAMShieldIntegrationTest(config = CaseSensitiveSchemaTest.CaseSensitiveServerConfig.class)
// MSSQL does not support setting the default schema per session
// TiDb does not support setting the default schema per session.
@DisabledForDatabases({"mssql", "tidb"})
public class CaseSensitiveSchemaTest extends AbstractDBSchemaTest {

    @InjectTestDatabase(config = CaseSensitiveDatabaseConfig.class)
    TestDatabase db;

    public static class CaseSensitiveServerConfig implements IAMShieldServerConfig {
        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {

            return switch (dbType()) {
                // DBs that convert unquoted to lower-case by default
                case PostgresTestDatabase.NAME -> config.option("db-schema", "KEYCLOAK");
                // DBs that convert unquoted to upper-case by default
                case "dev-file", "dev-mem" ->
                        config.option("db-url-properties", ";INIT=CREATE SCHEMA IF NOT EXISTS keycloak").option("db-schema", "keycloak");
                default -> config.option("db-schema", "keycloak");
            };
        }
    }

    public static class CaseSensitiveDatabaseConfig implements DatabaseConfig {
        @Override
        public DatabaseConfigBuilder configure(DatabaseConfigBuilder database) {
            if (PostgresTestDatabase.NAME.equals(dbType())) {
                database.initScript("org/keycloak/tests/db/case-sensitive-schema-postgres.sql");
            }
            return database;
        }
    }
}
