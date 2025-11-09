package org.iamshield.tests.client.authentication.external;

import org.iamshield.common.Profile;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;

public class ClientAuthIdpServerConfig implements IAMShieldServerConfig {

    @Override
    public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
        return config.features(Profile.Feature.CLIENT_AUTH_FEDERATED);
    }

}
