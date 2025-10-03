package org.iamshield.tests.db;

import org.iamshield.testframework.annotations.InjectTestDatabase;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.database.DatabaseConfig;
import org.iamshield.testframework.conditions.DisabledForDatabases;
import org.iamshield.testframework.database.DatabaseConfigBuilder;
import org.iamshield.testframework.database.PostgresTestDatabase;
import org.iamshield.testframework.database.TestDatabase;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

@IAMShieldIntegrationTest(config = PreserveSchemaCaseLiquibaseTest.PreserveSchemaCaseServerConfig.class)
// MSSQL does not support setting the default schema per session.
// TiDb does not support setting the default schema per session.
// Oracle image does not support configuring user/databases with '-'
@DisabledForDatabases({ "mssql", "oracle", "tidb" })
public class PreserveSchemaCaseLiquibaseTest extends AbstractDBSchemaTest {

    @InjectTestDatabase(config = PreserveSchemaCaseDatabaseConfig.class, lifecycle = LifeCycle.CLASS)
    TestDatabase db;

    public static class PreserveSchemaCaseServerConfig implements IAMShieldServerConfig {
        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            switch (dbType()) {
                case "dev-file":
                case "dev-mem":
                    config.option("db-url-properties", ";INIT=CREATE SCHEMA IF NOT EXISTS \"keycloak-t\"");
            }
            return config.option("db-schema", "keycloak-t");
        }
    }

    private static class PreserveSchemaCaseDatabaseConfig implements DatabaseConfig {
        @Override
        public DatabaseConfigBuilder configure(DatabaseConfigBuilder database) {
            if (dbType().equals(PostgresTestDatabase.NAME)) {
                return database.initScript("org/keycloak/tests/db/preserve-schema-case-liquibase-postgres.sql");
            }
            return database.database("keycloak-t");
        }
    }
}
