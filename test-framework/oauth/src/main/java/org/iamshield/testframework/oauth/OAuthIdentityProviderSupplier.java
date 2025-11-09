package org.iamshield.testframework.oauth;

import com.sun.net.httpserver.HttpServer;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierHelpers;
import org.iamshield.testframework.oauth.annotations.InjectOAuthIdentityProvider;

public class OAuthIdentityProviderSupplier implements Supplier<OAuthIdentityProvider, InjectOAuthIdentityProvider> {

    @Override
    public OAuthIdentityProvider getValue(InstanceContext<OAuthIdentityProvider, InjectOAuthIdentityProvider> instanceContext) {
        HttpServer httpServer = instanceContext.getDependency(HttpServer.class);
        OAuthIdentityProviderConfig config = SupplierHelpers.getInstance(instanceContext.getAnnotation().config());
        OAuthIdentityProviderConfigBuilder configBuilder = new OAuthIdentityProviderConfigBuilder();
        OAuthIdentityProviderConfigBuilder.OAuthIdentityProviderConfiguration configuration = config.configure(configBuilder).build();

        return new OAuthIdentityProvider(httpServer, configuration);
    }

    @Override
    public void close(InstanceContext<OAuthIdentityProvider, InjectOAuthIdentityProvider> instanceContext) {
        instanceContext.getValue().close();
    }

    @Override
    public boolean compatible(InstanceContext<OAuthIdentityProvider, InjectOAuthIdentityProvider> a, RequestedInstance<OAuthIdentityProvider, InjectOAuthIdentityProvider> b) {
        return a.getAnnotation().equals(b.getAnnotation());
    }

}
