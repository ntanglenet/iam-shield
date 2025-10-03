package org.iamshield.testsuite.broker;

import static org.iamshield.testsuite.broker.BrokerTestTools.createIdentityProvider;

import java.util.List;
import java.util.Map;
import org.iamshield.broker.oidc.OIDCIdentityProviderConfig;
import org.iamshield.broker.oidc.OIDCIdentityProviderFactory;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;

public class OidcAccessTokenOnlyClaimsUserAttributeMapperTest extends OidcUserAttributeMapperTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration() {

            private static final String OIDC_IDP_ALIAS = "oidc-idp";

            @Override
            public IdentityProviderRepresentation setUpIdentityProvider(
                IdentityProviderSyncMode syncMode) {
                final IdentityProviderRepresentation idp = createIdentityProvider(OIDC_IDP_ALIAS,
                    OIDCIdentityProviderFactory.PROVIDER_ID);

                final Map<String, String> config = idp.getConfig();
                applyDefaultConfiguration(config, syncMode);
                config.put(OIDCIdentityProviderConfig.IS_ACCESS_TOKEN_JWT, "true");

                return idp;
            }

            @Override
            public String getIDPAlias() {
                return OIDC_IDP_ALIAS;
            }

            @Override
            public List<ClientRepresentation> createProviderClients() {
                List<ClientRepresentation> clientsRepList = super.createProviderClients();
                clientsRepList.stream()
                    .flatMap(clientRepresentation -> clientRepresentation.getProtocolMappers().stream())
                    .map(ProtocolMapperRepresentation::getConfig)
                    .forEach(protocolMapperConfig -> {
                        protocolMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
                        protocolMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "false");
                        protocolMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "false");
                    });

                return clientsRepList;
            }
        };
    }
}
