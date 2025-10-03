package org.iamshield.testframework.oauth;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierHelpers;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ClientConfig;
import org.iamshield.testframework.realm.ClientConfigBuilder;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.server.IAMShieldUrls;
import org.iamshield.testframework.util.ApiUtil;
import org.openqa.selenium.WebDriver;

public class OAuthClientSupplier implements Supplier<OAuthClient, InjectOAuthClient> {

    @Override
    public OAuthClient getValue(InstanceContext<OAuthClient, InjectOAuthClient> instanceContext) {
        InjectOAuthClient annotation = instanceContext.getAnnotation();

        IAMShieldUrls keycloakUrls = instanceContext.getDependency(IAMShieldUrls.class);
        CloseableHttpClient httpClient = (CloseableHttpClient) instanceContext.getDependency(HttpClient.class);
        WebDriver webDriver = instanceContext.getDependency(WebDriver.class);
        TestApp testApp = instanceContext.getDependency(TestApp.class);

        ManagedRealm realm = instanceContext.getDependency(ManagedRealm.class, annotation.realmRef());

        String redirectUri = testApp.getRedirectionUri();

        ClientConfig clientConfig = SupplierHelpers.getInstance(annotation.config());
        ClientRepresentation testAppClient = clientConfig.configure(ClientConfigBuilder.create())
                .redirectUris(redirectUri)
                .build();

        if (annotation.kcAdmin()) {
            testAppClient.setAdminUrl(testApp.getAdminUri());
        }

        String clientId = testAppClient.getClientId();
        String clientSecret = testAppClient.getSecret();

        ApiUtil.handleCreatedResponse(realm.admin().clients().create(testAppClient));

        OAuthClient oAuthClient = new OAuthClient(keycloakUrls.getBase(), httpClient, webDriver);
        oAuthClient.config().realm(realm.getName()).client(clientId, clientSecret).redirectUri(redirectUri);
        return oAuthClient;
    }

    @Override
    public boolean compatible(InstanceContext<OAuthClient, InjectOAuthClient> a, RequestedInstance<OAuthClient, InjectOAuthClient> b) {
        return a.getAnnotation().ref().equals(b.getAnnotation().ref());
    }

    @Override
    public void close(InstanceContext<OAuthClient, InjectOAuthClient> instanceContext) {
        instanceContext.getValue().close();
    }
}
