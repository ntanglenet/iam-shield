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
package org.iamshield.crypto;

import org.iamshield.common.VerificationException;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.keys.loader.PublicKeyStorageManager;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;

public class ClientAsymmetricSignatureVerifierContext extends AsymmetricSignatureVerifierContext {

    public ClientAsymmetricSignatureVerifierContext(IAMShieldSession session, ClientModel client, JWSInput input) throws VerificationException {
        super(getKey(session, client, input));
    }

    private static KeyWrapper getKey(IAMShieldSession session, ClientModel client, JWSInput input) throws VerificationException {
        KeyWrapper key = PublicKeyStorageManager.getClientPublicKeyWrapper(session, client, input);
        if (key == null) {
            throw new VerificationException("Key not found");
        }
        if (!KeyType.RSA.equals(key.getType())) {
            throw new VerificationException("Key Type is not RSA: " + key.getType());
        }
        if (key.getAlgorithm() == null) {
            // defaults to the algorithm set to the JWS
            // validations should be performed prior to verifying signature in case there are restrictions on the algorithms
            // that can used for signing
            key.setAlgorithm(input.getHeader().getRawAlgorithm());
        } else if (!key.getAlgorithm().equals(input.getHeader().getRawAlgorithm())) {
            throw new VerificationException("Key Algorithms are different, key-algorithm=" + key.getAlgorithm()
                    + " jwt-algorithm=" + input.getHeader().getRawAlgorithm());
        }
        return key;
    }
}
