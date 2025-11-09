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
package org.iamshield.social.paypal;

import org.iamshield.broker.oidc.OAuth2IdentityProviderConfig;
import org.iamshield.broker.provider.AbstractIdentityProviderFactory;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.broker.social.SocialIdentityProviderFactory;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * @author Petter Lysne
 */
public class PayPalIdentityProviderFactory extends AbstractIdentityProviderFactory<PayPalIdentityProvider> implements SocialIdentityProviderFactory<PayPalIdentityProvider> {

    public static final String PROVIDER_ID = "paypal";

    @Override
    public String getName() {
        return "PayPal";
    }

    @Override
    public PayPalIdentityProvider create(IAMShieldSession session, IdentityProviderModel model) {
        return new PayPalIdentityProvider(session, new PayPalIdentityProviderConfig(model));
    }

    @Override
    public PayPalIdentityProviderConfig createConfig() {
        return new PayPalIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("sandbox")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Target Sandbox")
                .helpText("Target PayPal's sandbox environment")
                .add().build();
    }
}
