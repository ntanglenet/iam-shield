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

package org.iamshield.keys.loader;

import org.jboss.logging.Logger;
import org.iamshield.authentication.authenticators.client.JWTClientAuthenticator;
import org.iamshield.common.util.KeyUtils;
import org.iamshield.crypto.JavaAlgorithm;
import org.iamshield.crypto.KeyType;
import org.iamshield.crypto.KeyUse;
import org.iamshield.crypto.KeyWrapper;
import org.iamshield.crypto.PublicKeysWrapper;
import org.iamshield.jose.jwk.JSONWebKeySet;
import org.iamshield.jose.jwk.JWK;
import org.iamshield.keys.PublicKeyLoader;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ModelException;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.iamshield.protocol.oidc.utils.JWKSHttpUtils;
import org.iamshield.representations.idm.CertificateRepresentation;
import org.iamshield.services.util.CertificateInfoHelper;
import org.iamshield.services.util.ResolveRelative;
import org.iamshield.util.JWKSUtils;
import org.iamshield.util.JsonSerialization;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientPublicKeyLoader implements PublicKeyLoader {

    private static final Logger logger = Logger.getLogger(ClientPublicKeyLoader.class);

    private final IAMShieldSession session;
    private final ClientModel client;
    private final JWK.Use keyUse;

    public ClientPublicKeyLoader(IAMShieldSession session, ClientModel client) {
        this.session = session;
        this.client = client;
        this.keyUse = JWK.Use.SIG;
    }

    public ClientPublicKeyLoader(IAMShieldSession session, ClientModel client, JWK.Use keyUse) {
        this.session = session;
        this.client = client;
        this.keyUse = keyUse;
    }

    @Override
    public PublicKeysWrapper loadKeys() throws Exception {
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
        if (config.isUseJwksUrl()) {
            String jwksUrl = config.getJwksUrl();
            jwksUrl = ResolveRelative.resolveRelativeUri(session, client.getRootUrl(), jwksUrl);
            JSONWebKeySet jwks = JWKSHttpUtils.sendJwksRequest(session, jwksUrl);
            return JWKSUtils.getKeyWrappersForUse(jwks, keyUse, true);
        } else if (config.isUseJwksString()) {
            JSONWebKeySet jwks = JsonSerialization.readValue(config.getJwksString(), JSONWebKeySet.class);
            return JWKSUtils.getKeyWrappersForUse(jwks, keyUse);
        } else if (keyUse == JWK.Use.SIG) {
            try {
                CertificateRepresentation certInfo = CertificateInfoHelper.getCertificateFromClient(client, JWTClientAuthenticator.ATTR_PREFIX);
                KeyWrapper publicKey = getSignatureValidationKey(certInfo);
                return new PublicKeysWrapper(Collections.singletonList(publicKey));
            } catch (ModelException me) {
                logger.warnf(me, "Unable to retrieve publicKey for verify signature of client '%s' . Error details: %s", client.getClientId(), me.getMessage());
                return PublicKeysWrapper.EMPTY;
            }
        } else {
            logger.warnf("Unable to retrieve publicKey of client '%s' for the specified purpose other than verifying signature", client.getClientId());
            return PublicKeysWrapper.EMPTY;
        }
    }

    private static KeyWrapper getSignatureValidationKey(CertificateRepresentation certInfo) throws ModelException {
        KeyWrapper keyWrapper = new KeyWrapper();
        String encodedCertificate = certInfo.getCertificate();
        String encodedPublicKey = certInfo.getPublicKey();

        if (encodedCertificate == null && encodedPublicKey == null) {
            throw new ModelException("Client doesn't have certificate or publicKey configured");
        }

        if (encodedCertificate != null && encodedPublicKey != null) {
            throw new ModelException("Client has both publicKey and certificate configured");
        }

        keyWrapper.setUse(KeyUse.SIG);
        String kid = null;
        if (encodedCertificate != null) {
            X509Certificate clientCert = IAMShieldModelUtils.getCertificate(encodedCertificate);
            // Check if we have kid in DB, generate otherwise
            kid = certInfo.getKid() != null ? certInfo.getKid() : KeyUtils.createKeyId(clientCert.getPublicKey());
            keyWrapper.setKid(kid);
            keyWrapper.setPublicKey(clientCert.getPublicKey());
            keyWrapper.setType(JavaAlgorithm.getKeyType(clientCert.getPublicKey().getAlgorithm()));
            keyWrapper.setCertificate(clientCert);
            keyWrapper.setIsDefaultClientCertificate(true);
            if (KeyType.OKP.equals(keyWrapper.getType())) {
                keyWrapper.setCurve(clientCert.getPublicKey().getAlgorithm());
            }
        } else {
            PublicKey publicKey = IAMShieldModelUtils.getPublicKey(encodedPublicKey);
            // Check if we have kid in DB, generate otherwise
            kid = certInfo.getKid() != null ? certInfo.getKid() : KeyUtils.createKeyId(publicKey);
            keyWrapper.setKid(kid);
            keyWrapper.setPublicKey(publicKey);
            keyWrapper.setType(JavaAlgorithm.getKeyType(publicKey.getAlgorithm()));
            if (KeyType.OKP.equals(keyWrapper.getType())) {
                keyWrapper.setCurve(publicKey.getAlgorithm());
            }
        }
        return keyWrapper;
    }


}
