package org.iamshield.testsuite.broker;

import org.junit.Assert;
import org.junit.Test;
import org.iamshield.admin.client.resource.IdentityProviderResource;
import org.iamshield.broker.oidc.OIDCIdentityProvider;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.jose.jws.JWSInputException;
import org.iamshield.protocol.ProtocolMapperUtils;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.iamshield.protocol.oidc.mappers.UserSessionNoteMapper;
import org.iamshield.representations.IDToken;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;
import org.iamshield.testsuite.util.ClientBuilder;
import org.iamshield.testsuite.util.broker.OIDCIdentityProviderConfigRep;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;
import org.iamshield.testsuite.util.oauth.AuthorizationEndpointResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.iamshield.testsuite.broker.BrokerTestTools.getConsumerRoot;

public class KcOidcBrokerNonceParameterTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration() {
            @Override
            public List<ClientRepresentation> createConsumerClients() {
                List<ClientRepresentation> clients = new ArrayList<>(super.createConsumerClients());
                
                ClientRepresentation client = ClientBuilder.create().clientId("consumer-client")
                        .publicClient()
                        .redirectUris(getConsumerRoot() + "/auth/realms/master/app/auth/*")
                        .publicClient().build();

                // add the federated ID token to the protocol ID token
                ProtocolMapperRepresentation consumerSessionNoteToClaimMapper = new ProtocolMapperRepresentation();
                consumerSessionNoteToClaimMapper.setName(OIDCIdentityProvider.FEDERATED_ID_TOKEN);
                consumerSessionNoteToClaimMapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
                consumerSessionNoteToClaimMapper.setProtocolMapper(UserSessionNoteMapper.PROVIDER_ID);
                consumerSessionNoteToClaimMapper.setConfig(Map.of(ProtocolMapperUtils.USER_SESSION_NOTE, OIDCIdentityProvider.FEDERATED_ID_TOKEN,
                        OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, OIDCIdentityProvider.FEDERATED_ID_TOKEN,
                        OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, Boolean.TRUE.toString()));
                client.setProtocolMappers(Arrays.asList(consumerSessionNoteToClaimMapper));

                clients.add(client);

                return clients;
            }
        };
    }

    @Override
    protected void loginUser() {
        updateExecutions(AbstractBrokerTest::disableUpdateProfileOnFirstLogin);

        oauth.realm(bc.consumerRealmName());
        oauth.clientId("consumer-client");

        AuthorizationEndpointResponse authzResponse = doLoginSocial(oauth, bc.getIDPAlias(), bc.getUserLogin(), bc.getUserPassword(), "123456");
        String code = authzResponse.getCode();
        AccessTokenResponse response = oauth.doAccessTokenRequest(code);
        IDToken idToken = toIdToken(response.getIdToken());
        
        Assert.assertEquals("123456", idToken.getNonce());
        String federatedIdTokenString = (String) idToken.getOtherClaims().get(OIDCIdentityProvider.FEDERATED_ID_TOKEN);
        Assert.assertNotNull(federatedIdTokenString);
        IDToken federatedIdToken = toIdToken(federatedIdTokenString);
        Assert.assertNotNull(federatedIdToken.getNonce());
    }
    
    @Test
    public void testNonceNotSet() {
        updateExecutions(AbstractBrokerTest::disableUpdateProfileOnFirstLogin);

        // do not send nonce at IDP provider level either
        IdentityProviderResource idpRes = adminClient.realm(bc.consumerRealmName()).identityProviders().get(BrokerTestConstants.IDP_OIDC_ALIAS);
        IdentityProviderRepresentation idpRep = idpRes.toRepresentation();
        OIDCIdentityProviderConfigRep cfg = new OIDCIdentityProviderConfigRep(idpRep);
        cfg.setDisableNonce(true);
        idpRes.update(idpRep);

        oauth.realm(bc.consumerRealmName());
        oauth.clientId("consumer-client");

        AuthorizationEndpointResponse authzResponse = doLoginSocial(oauth, bc.getIDPAlias(), bc.getUserLogin(), bc.getUserPassword(), null);
        String code = authzResponse.getCode();
        AccessTokenResponse response = oauth.doAccessTokenRequest(code);
        IDToken idToken = toIdToken(response.getIdToken());

        Assert.assertNull(idToken.getNonce());
        String federatedIdTokenString = (String) idToken.getOtherClaims().get(OIDCIdentityProvider.FEDERATED_ID_TOKEN);
        Assert.assertNotNull(federatedIdTokenString);
        IDToken federatedIdToken = toIdToken(federatedIdTokenString);
        Assert.assertNull(federatedIdToken.getNonce());
    }

    protected IDToken toIdToken(String encoded) {
        IDToken idToken;

        try {
            idToken = new JWSInput(encoded).readJsonContent(IDToken.class);
        } catch (JWSInputException cause) {
            throw new RuntimeException("Failed to deserialize RPT", cause);
        }
        return idToken;
    }
}
