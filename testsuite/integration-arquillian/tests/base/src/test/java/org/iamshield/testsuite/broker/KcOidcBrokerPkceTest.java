package org.iamshield.testsuite.broker;

import org.iamshield.OAuth2Constants;
import org.iamshield.broker.oidc.OAuth2IdentityProviderConfig;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.representations.idm.IdentityProviderRepresentation;

public class KcOidcBrokerPkceTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration() {
            @Override public IdentityProviderRepresentation setUpIdentityProvider(IdentityProviderSyncMode syncMode) {
                IdentityProviderRepresentation provider = super.setUpIdentityProvider(syncMode);

                provider.getConfig().put(OAuth2IdentityProviderConfig.PKCE_ENABLED, "true");
                provider.getConfig().put(OAuth2IdentityProviderConfig.PKCE_METHOD, OAuth2Constants.PKCE_METHOD_S256);

                return provider;
            }
        };
    }
}
