/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.broker.oidc;

import org.iamshield.broker.oidc.IAMShieldOIDCIdentityProvider;
import org.iamshield.broker.oidc.OIDCIdentityProviderConfig;
import org.iamshield.broker.oidc.OIDCIdentityProviderFactory;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public class LegacyIdIdentityProviderFactory extends OIDCIdentityProviderFactory {

    public static final String PROVIDER_ID = "legacy-id-idp";

    @Override
    public String getName() {
        return PROVIDER_ID;
    }

    @Override
    public IAMShieldOIDCIdentityProvider create(IAMShieldSession session, IdentityProviderModel model) {
        return new LegacyIdIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}