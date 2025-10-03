package org.iamshield.testsuite.broker;

import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_ALIAS;
import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_PROVIDER_ID;
import static org.iamshield.testsuite.broker.BrokerTestTools.createIdentityProvider;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.iamshield.authentication.authenticators.client.JWTClientSecretAuthenticator;
import org.iamshield.crypto.Algorithm;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.protocol.oidc.OIDCConfigAttributes;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.IdentityProviderRepresentation;

public class KcOidcBrokerClientSecretJwtCustomSignAlgTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfigurationWithJWTAuthentication();
    }

    private class KcOidcBrokerConfigurationWithJWTAuthentication extends KcOidcBrokerConfiguration {

        String clientSecret = UUID.randomUUID().toString();
        String signAlg = Algorithm.HS384;
        
        @Override
        public List<ClientRepresentation> createProviderClients() {
            List<ClientRepresentation> clientsRepList = super.createProviderClients();
            log.info("Update provider clients to accept JWT authentication");
            for (ClientRepresentation client : clientsRepList) {
                if (client.getAttributes() == null) {
                    client.setAttributes(new HashMap<String, String>());
                }
                client.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
                client.setSecret(clientSecret);
                client.getAttributes().put(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, signAlg);
            }
            return clientsRepList;
        }

        @Override
        public IdentityProviderRepresentation setUpIdentityProvider(IdentityProviderSyncMode syncMode) {
            IdentityProviderRepresentation idp = createIdentityProvider(IDP_OIDC_ALIAS, IDP_OIDC_PROVIDER_ID);
            Map<String, String> config = idp.getConfig();
            applyDefaultConfiguration(config, syncMode);
            config.put("clientAuthMethod", OIDCLoginProtocol.CLIENT_SECRET_JWT);
            config.put("clientSecret", clientSecret);
            config.put("clientAssertionSigningAlg", signAlg);
            return idp;
        }
    }
}
