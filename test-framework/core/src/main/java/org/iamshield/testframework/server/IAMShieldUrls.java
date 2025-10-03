package org.iamshield.testframework.server;

import org.iamshield.common.util.IAMShieldUriBuilder;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;

import java.net.MalformedURLException;
import java.net.URL;

public class IAMShieldUrls {

    private final String baseUrl;
    private final String managementBaseUrl;

    public IAMShieldUrls(String baseUrl, String managementBaseUrl) {
        this.baseUrl = baseUrl;
        this.managementBaseUrl = managementBaseUrl;
    }

    public String getBase() {
        return baseUrl;
    }

    public URL getBaseUrl() {
        return toUrl(getBase());
    }

    public String getMasterRealm() {
        return baseUrl + "/realms/master";
    }

    public URL getMasterRealmUrl() {
        return toUrl(getMasterRealm());
    }

    public String getAdmin() {
        return baseUrl + "/admin";
    }

    public URL getAdminUrl() {
        return toUrl(getAdmin());
    }

    public IAMShieldUriBuilder getBaseBuilder() {
        return toBuilder(getBase());
    }

    public IAMShieldUriBuilder getAdminBuilder() {
        return toBuilder(getAdmin());
    }

    public String getMetric() {
        return managementBaseUrl + "/metrics";
    }

    private URL toUrl(String url) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private IAMShieldUriBuilder toBuilder(String url) {
        return IAMShieldUriBuilder.fromUri(url);
    }

    public String getToken(String realm) {
        return baseUrl + "/realms/" + realm + "/protocol/" + OIDCLoginProtocol.LOGIN_PROTOCOL + "/token";
    }
}
