package org.iamshield.testframework.infinispan;

import org.jboss.logging.Logger;
import org.iamshield.testframework.annotations.InjectInfinispanServer;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfigInterceptor;

public class InfinispanExternalServerSupplier implements Supplier<InfinispanServer, InjectInfinispanServer>, IAMShieldServerConfigInterceptor<InfinispanServer, InjectInfinispanServer> {

    private static final Logger LOGGER = Logger.getLogger(InfinispanExternalServerSupplier.class);

    @Override
    public InfinispanServer getValue(InstanceContext<InfinispanServer, InjectInfinispanServer> instanceContext) {
        InfinispanServer server = InfinispanExternalServer.create();
        getLogger().info("Starting Infinispan Server");

        long start = System.currentTimeMillis();

        server.start();

        getLogger().infov("Infinispan server started in {0} ms", System.currentTimeMillis() - start);
        return server;
    }

    @Override
    public void close(InstanceContext<InfinispanServer, InjectInfinispanServer> instanceContext) {
        instanceContext.getValue().stop();
    }

    @Override
    public boolean compatible(InstanceContext<InfinispanServer, InjectInfinispanServer> a, RequestedInstance<InfinispanServer, InjectInfinispanServer> b) {
        return a.getSupplier().getRef(a.getAnnotation()).equals(b.getSupplier().getRef(a.getAnnotation()));
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_KEYCLOAK_SERVER;
    }

    @Override
    public IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder config, InstanceContext<InfinispanServer, InjectInfinispanServer> instanceContext) {
        InfinispanServer ispnServer = instanceContext.getValue();

        return config.options(ispnServer.serverConfig());
    }

    public Logger getLogger() {
        return LOGGER;
    }
}
