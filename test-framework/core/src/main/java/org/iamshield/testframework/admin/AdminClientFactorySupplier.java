package org.iamshield.testframework.admin;

import org.iamshield.testframework.annotations.InjectAdminClientFactory;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.server.IAMShieldServer;

public class AdminClientFactorySupplier implements Supplier<AdminClientFactory, InjectAdminClientFactory> {

    @Override
    public AdminClientFactory getValue(InstanceContext<AdminClientFactory, InjectAdminClientFactory> instanceContext) {
        IAMShieldServer server = instanceContext.getDependency(IAMShieldServer.class);
        return new AdminClientFactory(server.getBaseUrl());
    }

    @Override
    public boolean compatible(InstanceContext<AdminClientFactory, InjectAdminClientFactory> a, RequestedInstance<AdminClientFactory, InjectAdminClientFactory> b) {
        return true;
    }

    @Override
    public void close(InstanceContext<AdminClientFactory, InjectAdminClientFactory> instanceContext) {
        instanceContext.getValue().close();
    }

}
