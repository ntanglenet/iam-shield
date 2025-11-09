package org.iamshield.testsuite.broker;

import org.iamshield.broker.oidc.OIDCIdentityProviderConfig;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.representations.idm.IdentityProviderRepresentation;

import java.util.Map;


import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_ALIAS;
import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_PROVIDER_ID;
import static org.iamshield.testsuite.broker.BrokerTestConstants.REALM_PROV_NAME;
import static org.iamshield.testsuite.broker.BrokerTestTools.createIdentityProvider;
import static org.iamshield.testsuite.broker.BrokerTestTools.getProviderRoot;

public class KcOidcBrokerIdpPublicKeyMissingUseTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfigurationWithIdpPublicKeyMissingUse();
    }

    private class KcOidcBrokerConfigurationWithIdpPublicKeyMissingUse extends KcOidcBrokerConfiguration {

        @Override
        public IdentityProviderRepresentation setUpIdentityProvider(IdentityProviderSyncMode syncMode) {
            IdentityProviderRepresentation idp = createIdentityProvider(IDP_OIDC_ALIAS, IDP_OIDC_PROVIDER_ID);
            Map<String, String> config = idp.getConfig();
            applyDefaultConfiguration(config, syncMode);
            config.put("clientAuthMethod", OIDCLoginProtocol.CLIENT_SECRET_BASIC);
            config.put(OIDCIdentityProviderConfig.JWKS_URL,
                    getProviderRoot() + "/auth/realms/" + REALM_PROV_NAME + "/missing-use-jwks/jwks");
            return idp;
        }

    }
}
