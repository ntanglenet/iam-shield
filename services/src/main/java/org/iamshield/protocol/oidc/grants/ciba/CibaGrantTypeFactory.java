/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.iamshield.protocol.oidc.grants.ciba;

import org.iamshield.Config;
import org.iamshield.OAuth2Constants;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.oidc.grants.OAuth2GrantType;
import org.iamshield.protocol.oidc.grants.OAuth2GrantTypeFactory;
import org.iamshield.provider.EnvironmentDependentProviderFactory;

/**
 * Factory for OpenID Connect Client-Initiated Backchannel Authentication Flow
 *
 * @author <a href="mailto:demetrio@carretti.pro">Dmitry Telegin</a>
 */
public class CibaGrantTypeFactory implements OAuth2GrantTypeFactory, EnvironmentDependentProviderFactory {

    public static final String GRANT_SHORTCUT = "ci";

    @Override
    public String getId() {
        return OAuth2Constants.CIBA_GRANT_TYPE;
    }

    @Override
    public String getShortcut() {
        return GRANT_SHORTCUT;
    }

    @Override
    public OAuth2GrantType create(IAMShieldSession session) {
        return new CibaGrantType();
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.CIBA);
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

}
