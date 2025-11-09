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
package org.iamshield.keys;

import org.iamshield.component.ComponentModel;
import org.iamshield.component.ComponentValidationException;
import org.iamshield.crypto.Algorithm;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.ConfigurationValidationHelper;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.iamshield.provider.ProviderConfigProperty.LIST_TYPE;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public abstract class AbstractEddsaKeyProviderFactory implements KeyProviderFactory {

    protected static final String EDDSA_PRIVATE_KEY_KEY = "eddsaPrivateKey";
    protected static final String EDDSA_PUBLIC_KEY_KEY = "eddsaPublicKey";
    protected static final String EDDSA_ELLIPTIC_CURVE_KEY = "eddsaEllipticCurveKey";
    public static final String DEFAULT_EDDSA_ELLIPTIC_CURVE = Algorithm.Ed25519;

    protected static ProviderConfigProperty EDDSA_ELLIPTIC_CURVE_PROPERTY = new ProviderConfigProperty(EDDSA_ELLIPTIC_CURVE_KEY, 
            "Elliptic Curve", "Elliptic Curve used in EdDSA", LIST_TYPE,
            String.valueOf(DEFAULT_EDDSA_ELLIPTIC_CURVE), Algorithm.Ed25519, Algorithm.Ed448);
 
    public final static ProviderConfigurationBuilder configurationBuilder() {
        return ProviderConfigurationBuilder.create()
                .property(Attributes.PRIORITY_PROPERTY)
                .property(Attributes.ENABLED_PROPERTY)
                .property(Attributes.ACTIVE_PROPERTY);
    }

    @Override
    public void validateConfiguration(IAMShieldSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
                .checkLong(Attributes.PRIORITY_PROPERTY, false)
                .checkBoolean(Attributes.ENABLED_PROPERTY, false)
                .checkBoolean(Attributes.ACTIVE_PROPERTY, false);
    }

    public static KeyPair generateEddsaKeyPair(String curveName) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(curveName);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
