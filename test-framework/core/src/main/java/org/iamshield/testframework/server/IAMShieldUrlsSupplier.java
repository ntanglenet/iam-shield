package org.iamshield.testframework.server;

import org.iamshield.testframework.annotations.InjectIAMShieldUrls;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;

public class IAMShieldUrlsSupplier implements Supplier<IAMShieldUrls, InjectIAMShieldUrls> {

    @Override
    public IAMShieldUrls getValue(InstanceContext<IAMShieldUrls, InjectIAMShieldUrls> instanceContext) {
        IAMShieldServer server = instanceContext.getDependency(IAMShieldServer.class);
        return new IAMShieldUrls(server.getBaseUrl(), server.getManagementBaseUrl());
    }

    @Override
    public boolean compatible(InstanceContext<IAMShieldUrls, InjectIAMShieldUrls> a, RequestedInstance<IAMShieldUrls, InjectIAMShieldUrls> b) {
        return true;
    }
}
