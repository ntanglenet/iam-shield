/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.authentication.requiredactions;

import com.webauthn4j.anchor.KeyStoreTrustAnchorRepository;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;

import org.iamshield.Config;
import org.iamshield.Config.Scope;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.truststore.TruststoreProvider;

public class WebAuthnRegisterFactory implements RequiredActionFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "webauthn-register";

    @Override
    public RequiredActionProvider create(IAMShieldSession session) {
        WebAuthnRegister webAuthnRegister = null;
        TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
        if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
            webAuthnRegister = createProvider(session, new NullCertPathTrustworthinessVerifier());
        } else {
            KeyStoreTrustAnchorRepository keyStoreTrustAnchorRepository = new KeyStoreTrustAnchorRepository(truststoreProvider.getTruststore());
            DefaultCertPathTrustworthinessVerifier trustVerifier = new DefaultCertPathTrustworthinessVerifier(keyStoreTrustAnchorRepository);
            webAuthnRegister = createProvider(session, trustVerifier);
        }
        return webAuthnRegister;
    }

    protected WebAuthnRegister createProvider(IAMShieldSession session, CertPathTrustworthinessVerifier trustVerifier) {
         return new WebAuthnRegister(session, trustVerifier);
    }

    @Override
    public void init(Scope config) {
        // NOP
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        // NOP
    }

    @Override
    public void close() {
        // NOP
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Webauthn Register";
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.WEB_AUTHN);
    }
}
