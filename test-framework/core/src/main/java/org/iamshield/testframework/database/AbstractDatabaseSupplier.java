package org.iamshield.testframework.database;

import org.iamshield.testframework.annotations.InjectTestDatabase;
import org.iamshield.testframework.config.Config;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierHelpers;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.server.IAMShieldServer;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfigInterceptor;

public abstract class AbstractDatabaseSupplier implements Supplier<TestDatabase, InjectTestDatabase>, IAMShieldServerConfigInterceptor<TestDatabase, InjectTestDatabase> {

    @Override
    public TestDatabase getValue(InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        DatabaseConfigBuilder builder = DatabaseConfigBuilder
              .create()
              .preventReuse(instanceContext.getLifeCycle() != LifeCycle.GLOBAL);

        DatabaseConfig config = SupplierHelpers.getInstance(instanceContext.getAnnotation().config());
        builder = config.configure(builder);

        TestDatabase testDatabase = getTestDatabase();
        testDatabase.start(builder.build());
        return testDatabase;
    }

    @Override
    public boolean compatible(InstanceContext<TestDatabase, InjectTestDatabase> a, RequestedInstance<TestDatabase, InjectTestDatabase> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    abstract TestDatabase getTestDatabase();

    @Override
    public void close(InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        instanceContext.getValue().stop();
    }

    @Override
    public IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder serverConfig, InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        String kcServerType = Config.getSelectedSupplier(IAMShieldServer.class);
        TestDatabase database = instanceContext.getValue();

        // If both IAMShieldServer and TestDatabase run in container, we need to configure IAMShield with internal
        // url that is accessible within docker network
        if ("cluster".equals(kcServerType) &&
                database instanceof AbstractContainerTestDatabase containerDatabase) {
            return serverConfig.options(containerDatabase.serverConfig(true));
        }

        return serverConfig.options(database.serverConfig());
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_KEYCLOAK_SERVER;
    }
}
