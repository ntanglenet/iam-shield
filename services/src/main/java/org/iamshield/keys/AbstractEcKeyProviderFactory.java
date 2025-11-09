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
package org.iamshield.keys;

import org.iamshield.component.ComponentModel;
import org.iamshield.component.ComponentValidationException;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.ConfigurationValidationHelper;
import org.iamshield.provider.ProviderConfigurationBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public abstract class AbstractEcKeyProviderFactory<T extends KeyProvider> implements KeyProviderFactory<T> {

    public static final String DEFAULT_EC_ELLIPTIC_CURVE = "P-256";

    public final static ProviderConfigurationBuilder configurationBuilder() {
        return ProviderConfigurationBuilder.create()
                .property(Attributes.PRIORITY_PROPERTY)
                .property(Attributes.ENABLED_PROPERTY)
                .property(Attributes.ACTIVE_PROPERTY)
                .property(Attributes.EC_GENERATE_CERTIFICATE_PROPERTY);
    }

    @Override
    public void validateConfiguration(IAMShieldSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
                .checkLong(Attributes.PRIORITY_PROPERTY, false)
                .checkBoolean(Attributes.ENABLED_PROPERTY, false)
                .checkBoolean(Attributes.ACTIVE_PROPERTY, false)
                .checkBoolean(Attributes.EC_GENERATE_CERTIFICATE_PROPERTY, false);
    }

    public static KeyPair generateEcKeyPair(String keySpecName) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            SecureRandom randomGen = SecureRandom.getInstance("SHA1PRNG");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(keySpecName);
            keyGen.initialize(ecSpec, randomGen);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String convertECDomainParmNistRepToSecRep(String ecInNistRep) {
        // convert Elliptic Curve Domain Parameter Name in NIST to SEC which is used to generate its EC key
        String ecInSecRep = null;
        switch(ecInNistRep) {
            case "P-256" :
                ecInSecRep = "secp256r1";
                break;
            case "P-384" :
                ecInSecRep = "secp384r1";
                break;
            case "P-521" :
                ecInSecRep = "secp521r1";
                break;
            default :
                // return null
        }
        return ecInSecRep;
    }
}
