package org.iamshield.testframework.database;

import org.iamshield.common.Profile;
import org.iamshield.testframework.annotations.InjectTestDatabase;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

public class TiDBDatabaseSupplier extends AbstractDatabaseSupplier {

    @Override
    public String getAlias() {
        return "tidb";
    }

    @Override
    public IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder serverConfig, InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        IAMShieldServerConfigBuilder builder = super.intercept(serverConfig, instanceContext);
        builder.features(Profile.Feature.DB_TIDB);
        return builder;
    }

    @Override
    TestDatabase getTestDatabase() {
        return new TiDBTestDatabase();
    }

}
