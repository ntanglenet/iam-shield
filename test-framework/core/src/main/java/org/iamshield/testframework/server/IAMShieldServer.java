package org.iamshield.testframework.server;

public interface IAMShieldServer {

    void start(IAMShieldServerConfigBuilder keycloakServerConfigBuilder);

    void stop();

    String getBaseUrl();

    String getManagementBaseUrl();
}
