/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.protocol.oid4vc.issuance;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.oid4vc.OID4VCEnvironmentProviderFactory;
import org.iamshield.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.iamshield.protocol.oidc.rar.AuthorizationDetailsProcessorFactory;

/**
 * Factory for creating OID4VCI-specific authorization details processors.
 * This factory is only enabled when the OID4VCI feature is available.
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 */
public class OID4VCAuthorizationDetailsProcessorFactory implements AuthorizationDetailsProcessorFactory, OID4VCEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "oid4vci-authorization-details-processor";

    @Override
    public AuthorizationDetailsProcessor create(IAMShieldSession session) {
        return new OID4VCAuthorizationDetailsProcessor(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration needed
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        // Higher order means higher priority - OID4VCI should be checked first
        return 100;
    }
}
