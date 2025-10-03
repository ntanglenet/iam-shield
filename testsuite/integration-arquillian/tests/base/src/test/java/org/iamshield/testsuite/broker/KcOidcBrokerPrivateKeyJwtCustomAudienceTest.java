/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.iamshield.testsuite.broker;

import org.iamshield.authentication.authenticators.client.JWTClientAuthenticator;
import org.iamshield.crypto.Algorithm;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.representations.idm.KeysMetadataRepresentation.KeyMetadataRepresentation;
import org.iamshield.testsuite.util.KeyUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_ALIAS;
import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_PROVIDER_ID;
import static org.iamshield.testsuite.broker.BrokerTestTools.createIdentityProvider;
import static org.iamshield.testsuite.util.ServerURLs.AUTH_SERVER_HOST2;

public class KcOidcBrokerPrivateKeyJwtCustomAudienceTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfigurationWithJWTAuthentication();
    }

    private class KcOidcBrokerConfigurationWithJWTAuthentication extends KcOidcBrokerConfiguration {

        @Override
        public List<ClientRepresentation> createProviderClients() {
            List<ClientRepresentation> clientsRepList = super.createProviderClients();
            log.info("Update provider clients to accept JWT authentication");
            KeyMetadataRepresentation keyRep = KeyUtils.findActiveSigningKey(adminClient.realm(consumerRealmName()), Algorithm.RS256);
            for (ClientRepresentation client: clientsRepList) {
                client.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
                if (client.getAttributes() == null) {
                    client.setAttributes(new HashMap<String, String>());
                }
                client.getAttributes().put(JWTClientAuthenticator.CERTIFICATE_ATTR, keyRep.getCertificate());
            }
            return clientsRepList;
        }

        @Override
        public IdentityProviderRepresentation setUpIdentityProvider(IdentityProviderSyncMode syncMode) {
            IdentityProviderRepresentation idp = createIdentityProvider(IDP_OIDC_ALIAS, IDP_OIDC_PROVIDER_ID);
            Map<String, String> config = idp.getConfig();
            applyDefaultConfiguration(config, syncMode);
            config.put("clientSecret", null);
            config.put("clientAuthMethod", OIDCLoginProtocol.PRIVATE_KEY_JWT);
            config.put("clientAssertionAudience", "https://" + AUTH_SERVER_HOST2 + ":8543/auth/realms/provider");
            return idp;
        }

    }

}
