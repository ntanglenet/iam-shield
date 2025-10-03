/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.protocol.oidc.grants;

import org.iamshield.Config;

import org.iamshield.OAuth2Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

/**
 * Factory for OAuth 2.0 Client Credentials Grant
 *
 * @author <a href="mailto:demetrio@carretti.pro">Dmitry Telegin</a>
 */
public class ClientCredentialsGrantTypeFactory implements OAuth2GrantTypeFactory {

    @Override
    public String getId() {
        return OAuth2Constants.CLIENT_CREDENTIALS;
    }

    @Override
    public String getShortcut() {
        return "cc";
    }

    @Override
    public OAuth2GrantType create(IAMShieldSession session) {
        return new ClientCredentialsGrantType();
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
