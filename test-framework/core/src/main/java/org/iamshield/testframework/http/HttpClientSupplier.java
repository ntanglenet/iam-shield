package org.iamshield.testframework.http;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.iamshield.testframework.annotations.InjectHttpClient;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;

import java.io.IOException;

public class HttpClientSupplier implements Supplier<HttpClient, InjectHttpClient> {

    @Override
    public HttpClient getValue(InstanceContext<HttpClient, InjectHttpClient> instanceContext) {
        HttpClientBuilder builder = HttpClientBuilder.create();

        if (!instanceContext.getAnnotation().followRedirects()) {
            builder.disableRedirectHandling();
        }

        return builder.build();
    }

    @Override
    public void close(InstanceContext<HttpClient, InjectHttpClient> instanceContext) {
        try {
            ((CloseableHttpClient) instanceContext.getValue()).close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public boolean compatible(InstanceContext<HttpClient, InjectHttpClient> a, RequestedInstance<HttpClient, InjectHttpClient> b) {
        return a.getAnnotation().followRedirects() == b.getAnnotation().followRedirects();
    }

}
