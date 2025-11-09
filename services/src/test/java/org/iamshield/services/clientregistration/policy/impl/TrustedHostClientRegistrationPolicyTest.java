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
package org.iamshield.services.clientregistration.policy.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.iamshield.common.Profile;
import org.iamshield.common.crypto.CryptoIntegration;
import org.iamshield.common.crypto.CryptoProvider;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.iamshield.services.resteasy.ResteasyIAMShieldSession;
import org.iamshield.services.resteasy.ResteasyIAMShieldSessionFactory;

/**
 *
 * @author rmartinc
 */
public class TrustedHostClientRegistrationPolicyTest {

    private static IAMShieldSession session;

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        ResteasyIAMShieldSessionFactory sessionFactory = new ResteasyIAMShieldSessionFactory();
        sessionFactory.init();
        session = new ResteasyIAMShieldSession(sessionFactory);
    }

    @Test
    public void testLocalhostName() {
        TrustedHostClientRegistrationPolicyFactory factory = new TrustedHostClientRegistrationPolicyFactory();
        ComponentModel model = createComponentModel("localhost");
        TrustedHostClientRegistrationPolicy policy = (TrustedHostClientRegistrationPolicy) factory.create(session, model);

        assertTrue(policy.verifyHost("127.0.0.1"));
        assertFalse(policy.verifyHost("10.0.0.1"));
        policy.checkURLTrusted("https://localhost", policy.getTrustedHosts(), policy.getTrustedDomains());
        Assert.assertThrows(ClientRegistrationPolicyException.class, () -> policy.checkURLTrusted("https://otherhost",
                policy.getTrustedHosts(), policy.getTrustedDomains()));
    }

    @Test
    public void testLocalhostDomain() {
        TrustedHostClientRegistrationPolicyFactory factory = new TrustedHostClientRegistrationPolicyFactory();
        ComponentModel model = createComponentModel("*.localhost");
        TrustedHostClientRegistrationPolicy policy = (TrustedHostClientRegistrationPolicy) factory.create(session, model);

        assertTrue(policy.verifyHost("127.0.0.1"));
        assertFalse(policy.verifyHost("10.0.0.1"));
        policy.checkURLTrusted("https://localhost", policy.getTrustedHosts(), policy.getTrustedDomains());
        policy.checkURLTrusted("https://other.localhost", policy.getTrustedHosts(), policy.getTrustedDomains());
        Assert.assertThrows(ClientRegistrationPolicyException.class, () -> policy.checkURLTrusted("https://otherlocalhost",
                policy.getTrustedHosts(), policy.getTrustedDomains()));
    }

    @Test
    public void testLocalhostIP() {
        TrustedHostClientRegistrationPolicyFactory factory = new TrustedHostClientRegistrationPolicyFactory();
        ComponentModel model = createComponentModel("127.0.0.1");
        TrustedHostClientRegistrationPolicy policy = (TrustedHostClientRegistrationPolicy) factory.create(session, model);

        assertTrue(policy.verifyHost("127.0.0.1"));
        assertFalse(policy.verifyHost("10.0.0.1"));
        policy.checkURLTrusted("https://127.0.0.1", policy.getTrustedHosts(), policy.getTrustedDomains());
        Assert.assertThrows(ClientRegistrationPolicyException.class, () -> policy.checkURLTrusted("https://localhost",
                policy.getTrustedHosts(), policy.getTrustedDomains()));
    }

    @Test
    public void testGoogleCrawlBot() {
        // https://developers.google.com/search/blog/2006/09/how-to-verify-googlebot
        TrustedHostClientRegistrationPolicyFactory factory = new TrustedHostClientRegistrationPolicyFactory();
        ComponentModel model = createComponentModel("*.googlebot.com");
        TrustedHostClientRegistrationPolicy policy = (TrustedHostClientRegistrationPolicy) factory.create(session, model);

        policy.verifyHost("66.249.66.1");
        policy.checkURLTrusted("https://www.googlebot.com", policy.getTrustedHosts(), policy.getTrustedDomains());
        policy.checkURLTrusted("https://googlebot.com", policy.getTrustedHosts(), policy.getTrustedDomains());
        Assert.assertThrows(ClientRegistrationPolicyException.class, () -> policy.checkURLTrusted("https://www.othergooglebot.com",
                policy.getTrustedHosts(), policy.getTrustedDomains()));
    }

    private ComponentModel createComponentModel(String... hosts) {
        ComponentModel model = new ComponentModel();
        model.put(TrustedHostClientRegistrationPolicyFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH, "true");
        model.put(TrustedHostClientRegistrationPolicyFactory.CLIENT_URIS_MUST_MATCH, "true");
        model.getConfig().addAll(TrustedHostClientRegistrationPolicyFactory.TRUSTED_HOSTS, hosts);
        return model;
    }
}
