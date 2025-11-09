package org.iamshield.testframework.oauth;

import com.sun.net.httpserver.HttpServer;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.oauth.annotations.InjectTestApp;

public class TestAppSupplier implements Supplier<TestApp, InjectTestApp> {

    @Override
    public TestApp getValue(InstanceContext<TestApp, InjectTestApp> instanceContext) {
        HttpServer httpServer = instanceContext.getDependency(HttpServer.class);
        return new TestApp(httpServer);
    }

    @Override
    public boolean compatible(InstanceContext<TestApp, InjectTestApp> a, RequestedInstance<TestApp, InjectTestApp> b) {
        return true;
    }

    @Override
    public void close(InstanceContext<TestApp, InjectTestApp> instanceContext) {
        instanceContext.getValue().close();
    }

}
