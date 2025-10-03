package org.iamshield.testsuite.broker;

import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.representations.idm.IdentityProviderRepresentation;

import java.util.Map;


import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_ALIAS;
import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_PROVIDER_ID;
import static org.iamshield.testsuite.broker.BrokerTestTools.createIdentityProvider;

public class KcOidcBrokerClientSecretBasicAuthTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfigurationWithBasicAuthAuthentication();
    }

    private class KcOidcBrokerConfigurationWithBasicAuthAuthentication extends KcOidcBrokerConfiguration {

        @Override
        public IdentityProviderRepresentation setUpIdentityProvider(IdentityProviderSyncMode syncMode) {
            IdentityProviderRepresentation idp = createIdentityProvider(IDP_OIDC_ALIAS, IDP_OIDC_PROVIDER_ID);
            Map<String, String> config = idp.getConfig();
            applyDefaultConfiguration(config, syncMode);
            config.put("clientAuthMethod", OIDCLoginProtocol.CLIENT_SECRET_BASIC);
            return idp;
        }
        

    }
}
