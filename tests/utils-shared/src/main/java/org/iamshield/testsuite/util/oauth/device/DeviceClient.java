package org.iamshield.testsuite.util.oauth.device;

import org.iamshield.testsuite.util.oauth.AbstractOAuthClient;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;

public class DeviceClient {

    private final AbstractOAuthClient<?> client;

    public DeviceClient(AbstractOAuthClient<?> client) {
        this.client = client;
    }

    public DeviceAuthorizationRequest deviceAuthorizationRequest() {
        return new DeviceAuthorizationRequest(client);
    }

    public DeviceAuthorizationResponse doDeviceAuthorizationRequest() {
        return deviceAuthorizationRequest().send();
    }

    public DeviceTokenRequest deviceTokenRequest(String deviceCode) {
        return new DeviceTokenRequest(deviceCode, client);
    }

    public AccessTokenResponse doDeviceTokenRequest(String deviceCode) {
        return deviceTokenRequest(deviceCode).send();
    }

}
