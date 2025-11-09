package org.iamshield.testframework.http;

import com.sun.net.httpserver.HttpServer;
import org.iamshield.testframework.annotations.InjectHttpServer;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;

import java.io.IOException;
import java.net.InetSocketAddress;

public class HttpServerSupplier implements Supplier<HttpServer, InjectHttpServer> {

    @Override
    public HttpServer getValue(InstanceContext<HttpServer, InjectHttpServer> instanceContext) {
        try {
            HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 8500), 10);
            httpServer.start();
            return httpServer;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close(InstanceContext<HttpServer, InjectHttpServer> instanceContext) {
        instanceContext.getValue().stop(0);
    }

    @Override
    public boolean compatible(InstanceContext<HttpServer, InjectHttpServer> a, RequestedInstance<HttpServer, InjectHttpServer> b) {
        return true;
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

}
