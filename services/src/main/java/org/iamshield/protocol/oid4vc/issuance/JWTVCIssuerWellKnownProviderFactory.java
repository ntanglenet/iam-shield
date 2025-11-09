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
package org.iamshield.protocol.oid4vc.issuance;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.oid4vc.OID4VCEnvironmentProviderFactory;
import org.iamshield.wellknown.WellKnownProvider;
import org.iamshield.wellknown.WellKnownProviderFactory;

/**
 * {@link  WellKnownProviderFactory} implementation for JWT VC Issuer metadata at endpoint /.well-known/jwt-vc-issuer
 *
 * {@see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html#name-jwt-vc-issuer-metadata}
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class JWTVCIssuerWellKnownProviderFactory implements WellKnownProviderFactory, OID4VCEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "jwt-vc-issuer";

    @Override
    public WellKnownProvider create(IAMShieldSession session) {
        return new JWTVCIssuerWellKnownProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}