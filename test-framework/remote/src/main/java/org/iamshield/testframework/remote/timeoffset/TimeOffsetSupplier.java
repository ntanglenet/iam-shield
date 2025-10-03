package org.iamshield.testframework.remote.timeoffset;

import org.apache.http.client.HttpClient;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.remote.RemoteProviders;
import org.iamshield.testframework.server.IAMShieldUrls;

public class TimeOffsetSupplier implements Supplier<TimeOffSet, InjectTimeOffSet> {

    @Override
    public TimeOffSet getValue(InstanceContext<TimeOffSet, InjectTimeOffSet> instanceContext) {
        var httpClient = instanceContext.getDependency(HttpClient.class);
        var remoteProviders = instanceContext.getDependency(RemoteProviders.class);
        IAMShieldUrls keycloakUrls = instanceContext.getDependency(IAMShieldUrls.class);

        int initOffset = instanceContext.getAnnotation().offset();
        return new TimeOffSet(httpClient, keycloakUrls.getMasterRealm(), initOffset);
    }

    @Override
    public boolean compatible(InstanceContext<TimeOffSet, InjectTimeOffSet> a, RequestedInstance<TimeOffSet, InjectTimeOffSet> b) {
        return true;
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.METHOD;
    }

    @Override
    public void close(InstanceContext<TimeOffSet, InjectTimeOffSet> instanceContext) {
        TimeOffSet timeOffSet = instanceContext.getValue();
        if (timeOffSet.hasChanged()) {
            timeOffSet.set(0);
        }
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_KEYCLOAK_SERVER;
    }

}
