/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.iamshield.protocol.oidc.tokenexchange;

import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.oidc.TokenExchangeProvider;
import org.iamshield.protocol.oidc.TokenExchangeProviderFactory;
import org.iamshield.provider.EnvironmentDependentProviderFactory;

/**
 * Provider factory for external-internal token exchange
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ExternalToInternalTokenExchangeProviderFactory implements TokenExchangeProviderFactory, EnvironmentDependentProviderFactory {

    @Override
    public TokenExchangeProvider create(IAMShieldSession session) {
        return new ExternalToInternalTokenExchangeProvider();
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "external-internal";
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE_EXTERNAL_INTERNAL_V2);
    }

    @Override
    public int order() {
        // Bigger priority than V1, so it has preference if both V1 and V2 enabled. Also bigger priority than "standard", so it can verify if request is from external-token
        return 20;
    }
}
