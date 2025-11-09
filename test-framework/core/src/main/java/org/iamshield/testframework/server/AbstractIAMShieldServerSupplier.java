package org.iamshield.testframework.server;

import org.jboss.logging.Logger;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.infinispan.InfinispanServer;
import org.iamshield.testframework.config.Config;
import org.iamshield.testframework.database.TestDatabase;
import org.iamshield.testframework.injection.AbstractInterceptorHelper;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.Registry;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierHelpers;
import org.iamshield.testframework.injection.SupplierOrder;

public abstract class AbstractIAMShieldServerSupplier implements Supplier<IAMShieldServer, IAMShieldIntegrationTest> {

    @Override
    public IAMShieldServer getValue(InstanceContext<IAMShieldServer, IAMShieldIntegrationTest> instanceContext) {
        IAMShieldIntegrationTest annotation = instanceContext.getAnnotation();
        IAMShieldServerConfig serverConfig = SupplierHelpers.getInstance(annotation.config());

        IAMShieldServerConfigBuilder command = IAMShieldServerConfigBuilder.startDev()
                .bootstrapAdminClient(Config.getAdminClientId(), Config.getAdminClientSecret())
                .bootstrapAdminUser(Config.getAdminUsername(), Config.getAdminPassword());

        command.log().handlers(IAMShieldServerConfigBuilder.LogHandlers.CONSOLE);

        String supplierConfig = Config.getSupplierConfig(IAMShieldServer.class);
        if (supplierConfig != null) {
            IAMShieldServerConfig serverConfigOverride = SupplierHelpers.getInstance(supplierConfig);
            serverConfigOverride.configure(command);
        }

        command = serverConfig.configure(command);

        // Database startup and IAMShield connection setup
        if (requiresDatabase()) {
            instanceContext.getDependency(TestDatabase.class);
        }

        // External Infinispan startup and IAMShield connection setup
        if (command.isExternalInfinispanEnabled()) {
            instanceContext.getDependency(InfinispanServer.class);
        }

        ServerConfigInterceptorHelper interceptor = new ServerConfigInterceptorHelper(instanceContext.getRegistry());
        command = interceptor.intercept(command, instanceContext);

        command.log().fromConfig(Config.getConfig());

        getLogger().info("Starting IAMShield test server");
        if (getLogger().isDebugEnabled()) {
            getLogger().debugv("Startup command and options: \n\t{0}", String.join("\n\t", command.toArgs()));
        }

        long start = System.currentTimeMillis();

        IAMShieldServer server = getServer();
        server.start(command);

        getLogger().infov("IAMShield test server started in {0} ms", System.currentTimeMillis() - start);

        return server;
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public boolean compatible(InstanceContext<IAMShieldServer, IAMShieldIntegrationTest> a, RequestedInstance<IAMShieldServer, IAMShieldIntegrationTest> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public void close(InstanceContext<IAMShieldServer, IAMShieldIntegrationTest> instanceContext) {
        instanceContext.getValue().stop();
    }

    public abstract IAMShieldServer getServer();

    public abstract boolean requiresDatabase();

    public abstract Logger getLogger();

    @Override
    public int order() {
        return SupplierOrder.KEYCLOAK_SERVER;
    }

    private static class ServerConfigInterceptorHelper extends AbstractInterceptorHelper<IAMShieldServerConfigInterceptor, IAMShieldServerConfigBuilder> {

        private ServerConfigInterceptorHelper(Registry registry) {
            super(registry, IAMShieldServerConfigInterceptor.class);
        }

        @Override
        public IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder value, Supplier<?, ?> supplier, InstanceContext<?, ?> existingInstance) {
            if (supplier instanceof IAMShieldServerConfigInterceptor keycloakServerConfigInterceptor) {
                value = keycloakServerConfigInterceptor.intercept(value, existingInstance);
            }
            return value;
        }
    }

}
