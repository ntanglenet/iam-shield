/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.protocol.oidc.grants.device;


import org.iamshield.OAuth2Constants;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.protocol.oidc.grants.OAuth2GrantType;
import org.iamshield.Config;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.oidc.grants.OAuth2GrantTypeFactory;

/**
 * Factory for OAuth 2.0 Device Authorization Grant
 *
 * @author <a href="mailto:demetrio@carretti.pro">Dmitry Telegin</a>
 */
public class DeviceGrantTypeFactory implements OAuth2GrantTypeFactory, EnvironmentDependentProviderFactory {

    public static final String GRANT_SHORTCUT = "dg";

    @Override
    public String getId() {
        return OAuth2Constants.DEVICE_CODE_GRANT_TYPE;
    }

    @Override
    public String getShortcut() {
        return GRANT_SHORTCUT;
    }

    @Override
    public OAuth2GrantType create(IAMShieldSession session) {
        return new DeviceGrantType();
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.DEVICE_FLOW);
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
