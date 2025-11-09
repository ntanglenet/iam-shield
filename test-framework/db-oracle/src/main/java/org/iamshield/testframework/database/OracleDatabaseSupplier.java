package org.iamshield.testframework.database;

import org.iamshield.testframework.annotations.InjectTestDatabase;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

public class OracleDatabaseSupplier extends AbstractDatabaseSupplier {

    @Override
    public String getAlias() {
        return OracleTestDatabase.NAME;
    }

    @Override
    TestDatabase getTestDatabase() {
        return new OracleTestDatabase();
    }

    @Override
    public IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder serverConfig, InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        return super.intercept(serverConfig, instanceContext)
                .dependency("com.oracle.database.jdbc", "ojdbc17");
    }
}
