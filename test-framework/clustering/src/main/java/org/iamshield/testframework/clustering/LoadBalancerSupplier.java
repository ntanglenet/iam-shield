package org.iamshield.testframework.clustering;

import org.iamshield.testframework.annotations.InjectLoadBalancer;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.server.ClusteredIAMShieldServer;
import org.iamshield.testframework.server.IAMShieldServer;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfigInterceptor;

public class LoadBalancerSupplier implements Supplier<LoadBalancer, InjectLoadBalancer>, IAMShieldServerConfigInterceptor<LoadBalancer, InjectLoadBalancer> {

    @Override
    public LoadBalancer getValue(InstanceContext<LoadBalancer, InjectLoadBalancer> instanceContext) {
        IAMShieldServer server = instanceContext.getDependency(IAMShieldServer.class);

        if (server instanceof ClusteredIAMShieldServer clusteredIAMShieldServer) {
            return new LoadBalancer(clusteredIAMShieldServer);
        }

        throw new IllegalStateException("Load balancer can only be used with ClusteredIAMShieldServer");
    }

    @Override
    public void close(InstanceContext<LoadBalancer, InjectLoadBalancer> instanceContext) {
        instanceContext.getValue().close();
    }

    @Override
    public boolean compatible(InstanceContext<LoadBalancer, InjectLoadBalancer> a, RequestedInstance<LoadBalancer, InjectLoadBalancer> b) {
        return true;
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_REALM;
    }

    @Override
    public IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder serverConfig, InstanceContext<LoadBalancer, InjectLoadBalancer> instanceContext) {
        return serverConfig.option("hostname", LoadBalancer.HOSTNAME);
    }
}
