/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.common.util.PemUtils;
import org.iamshield.crypto.Algorithm;
import org.iamshield.crypto.KeyUse;
import org.iamshield.dom.saml.v2.protocol.AuthnRequestType;
import org.iamshield.representations.idm.KeysMetadataRepresentation;
import org.iamshield.saml.common.constants.JBossSAMLURIConstants;
import org.iamshield.saml.common.exceptions.ConfigurationException;
import org.iamshield.saml.common.exceptions.ParsingException;
import org.iamshield.saml.common.exceptions.ProcessingException;
import org.iamshield.saml.processing.api.saml.v2.request.SAML2Request;
import org.iamshield.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.iamshield.testsuite.util.KeyUtils;
import org.iamshield.testsuite.util.SamlClient;
import org.iamshield.testsuite.util.SamlClientBuilder;
import org.iamshield.testsuite.util.saml.SamlDocumentStepBuilder;
import org.w3c.dom.Document;

import jakarta.ws.rs.core.Response;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicReference;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.iamshield.testsuite.broker.BrokerTestTools.getConsumerRoot;
import static org.iamshield.testsuite.saml.AbstractSamlTest.SAML_CLIENT_ID_SALES_POST;
import static org.iamshield.testsuite.util.Matchers.isSamlResponse;
import static org.iamshield.testsuite.util.Matchers.statusCodeIsHC;

public abstract class AbstractKcSamlEncryptedElementsTest extends AbstractBrokerTest {

        private String encProviderId;
        private String sigProviderId;

        @Override
        protected BrokerConfiguration getBrokerConfiguration() {
            return KcSamlBrokerConfiguration.INSTANCE;
        }

        @Before
        public void setupKeys() {
            sigProviderId = KeyUtils.findActiveSigningKey(adminClient.realm(bc.consumerRealmName())).getProviderId();
            encProviderId = KeyUtils.findActiveEncryptingKey(adminClient.realm(bc.consumerRealmName()), Algorithm.RSA_OAEP).getProviderId();
            assertThat(sigProviderId, not(equalTo(encProviderId)));

        }

        @Test
        public void testEncryptedElementIsReadable() throws ConfigurationException, ParsingException, ProcessingException {
            KeysMetadataRepresentation.KeyMetadataRepresentation activeEncryptingKey = KeyUtils.findActiveEncryptingKey(adminClient.realm(bc.consumerRealmName()), Algorithm.RSA_OAEP);
            assertThat(activeEncryptingKey.getProviderId(), equalTo(encProviderId));
            sendDocumentWithEncryptedElement(PemUtils.decodePublicKey(activeEncryptingKey.getPublicKey()), XMLCipher.RSA_OAEP, null, null, true);
        }

        @Test
        public void testSignatureKeyEncryptedElementIsNotReadableWithoutDeprecatedMode() throws ConfigurationException, ParsingException, ProcessingException {
            KeysMetadataRepresentation.KeyMetadataRepresentation activeSignatureKey = KeyUtils.findActiveSigningKey(adminClient.realm(bc.consumerRealmName()));
            assertThat(activeSignatureKey.getProviderId(), equalTo(sigProviderId));
            sendDocumentWithEncryptedElement(PemUtils.decodePublicKey(activeSignatureKey.getPublicKey()), XMLCipher.RSA_OAEP, null, null, false);
        }

        @Test
        public void testUseDifferentEncryptionAlgorithm() throws Exception {
            RealmResource realm = adminClient.realm(bc.consumerRealmName());
            try (AutoCloseable ac = KeyUtils.generateNewRealmKey(realm, KeyUse.ENC, Algorithm.RSA1_5)) {
                KeysMetadataRepresentation.KeyMetadataRepresentation key = KeyUtils.findRealmKeys(realm, k -> k.getAlgorithm().equals(Algorithm.RSA1_5))
                        .findFirst()
                        .orElseThrow(() -> new RuntimeException("Cannot find key created on the previous line"));

                sendDocumentWithEncryptedElement(PemUtils.decodePublicKey(key.getPublicKey()), XMLCipher.RSA_v1dot5, null, null, true);
            }
        }

        @Test
        public void testRsaOaepAlgorithm() throws Exception {
            RealmResource realm = adminClient.realm(bc.consumerRealmName());
            KeysMetadataRepresentation.KeyMetadataRepresentation key = KeyUtils.findActiveEncryptingKey(realm, Algorithm.RSA_OAEP);
            assertThat(key.getProviderId(), equalTo(encProviderId));
            sendDocumentWithEncryptedElement(PemUtils.decodePublicKey(key.getPublicKey()), XMLCipher.RSA_OAEP_11, XMLCipher.SHA256, EncryptionConstants.MGF1_SHA256, true);
        }

        protected abstract SamlDocumentStepBuilder.Saml2DocumentTransformer encryptDocument(PublicKey publicKey, String keyEncryptionAlgorithm, String keyEncryptionDigestMethod, String keyEncryptionMgfAlgorithm);

        private void sendDocumentWithEncryptedElement(PublicKey publicKey, String keyEncryptionAlgorithm, String keyEncryptionDigestMethod, String keyEncryptionMgfAlgorithm, boolean shouldPass) throws ConfigurationException, ParsingException, ProcessingException {
            createRolesForRealm(bc.consumerRealmName());

            AuthnRequestType loginRep = SamlClient.createLoginRequestDocument(SAML_CLIENT_ID_SALES_POST + ".dot/ted", getConsumerRoot() + "/sales-post/saml", null);

            Document doc = SAML2Request.convert(loginRep);

            final AtomicReference<String> username = new AtomicReference<>();
            assertThat(adminClient.realm(bc.consumerRealmName()).users().search(username.get()), hasSize(0));

            SamlClientBuilder samlClientBuilder = new SamlClientBuilder()
                    .authnRequest(getConsumerSamlEndpoint(bc.consumerRealmName()), doc, SamlClient.Binding.POST).build()   // Request to consumer IdP
                    .login().idp(bc.getIDPAlias()).build()

                    .processSamlResponse(SamlClient.Binding.POST)    // AuthnRequest to producer IdP
                    .targetAttributeSamlRequest()
                    .build()

                    .login().user(bc.getUserLogin(), bc.getUserPassword()).build()

                    .processSamlResponse(SamlClient.Binding.POST)    // Response from producer IdP
                    .transformDocument(encryptDocument(publicKey, keyEncryptionAlgorithm, keyEncryptionDigestMethod, keyEncryptionMgfAlgorithm))
                    .build();

            if (shouldPass) {
                // first-broker flow
                SAMLDocumentHolder samlResponse =
                        samlClientBuilder.updateProfile().firstName("a").lastName("b").email(bc.getUserEmail()).build()
                                .followOneRedirect()
                                .getSamlResponse(SamlClient.Binding.POST);       // Response from consumer IdP

                assertThat(samlResponse, Matchers.notNullValue());
                assertThat(samlResponse.getSamlObject(), isSamlResponse(JBossSAMLURIConstants.STATUS_SUCCESS));

                assertThat(adminClient.realm(bc.consumerRealmName()).users().search(username.get()), hasSize(1));
            } else {
                samlClientBuilder.executeAndTransform(response -> {
                    assertThat(response, statusCodeIsHC(Response.Status.BAD_REQUEST));
                    return null;
                });
            }

        }
    }


