package org.iamshield.testframework.remote;

import org.iamshield.testframework.annotations.InjectTestDatabase;
import org.iamshield.testframework.database.TestDatabase;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfigInterceptor;

public class RemoteProvidersSupplier implements Supplier<RemoteProviders, InjectRemoteProviders>, IAMShieldServerConfigInterceptor<TestDatabase, InjectTestDatabase> {

    @Override
    public RemoteProviders getValue(InstanceContext<RemoteProviders, InjectRemoteProviders> instanceContext) {
        return new RemoteProviders();
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public boolean compatible(InstanceContext<RemoteProviders, InjectRemoteProviders> a, RequestedInstance<RemoteProviders, InjectRemoteProviders> b) {
        return true;
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_KEYCLOAK_SERVER;
    }

    @Override
    public IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder serverConfig, InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        return serverConfig.dependency("org.iamshield.testframework", "keycloak-test-framework-remote-providers");
    }
}
