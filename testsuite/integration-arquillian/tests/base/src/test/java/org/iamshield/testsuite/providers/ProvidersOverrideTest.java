/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.providers;

import org.junit.Test;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.authenticators.directgrant.ValidateOTP;
import org.iamshield.authentication.authenticators.directgrant.ValidatePassword;
import org.iamshield.authentication.authenticators.directgrant.ValidateUsername;
import org.iamshield.email.EmailSenderProvider;
import org.iamshield.examples.providersoverride.CustomDefaultEmailSenderProvider2;
import org.iamshield.examples.providersoverride.CustomLoginFormsProvider;
import org.iamshield.examples.providersoverride.CustomValidatePassword2;
import org.iamshield.examples.providersoverride.CustomValidateUsername;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.provider.Provider;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.AbstractIAMShieldTest;
import org.iamshield.testsuite.Assert;

import java.util.List;

/**
 * Test for having multiple providerFactory of smae SPI with same providerId
 * 
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ProvidersOverrideTest extends AbstractIAMShieldTest {

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
    }

    @Test
    public void testBuiltinAuthenticatorsOverride() {
        // The custom provider would be preferred over the internal ValidateUsername. Both has same order, so custom provider would be chosen (backwards compatibility with previous versions)
        testProviderImplementationClass(Authenticator.class, ValidateUsername.PROVIDER_ID, CustomValidateUsername.class);

        // The provider with highest order is chosen
        testProviderImplementationClass(Authenticator.class, ValidatePassword.PROVIDER_ID, CustomValidatePassword2.class);

        // The builtin ValidateOTP class is chosen as it has higher order than the CustomValidateOTP
        testProviderImplementationClass(Authenticator.class, ValidateOTP.PROVIDER_ID, ValidateOTP.class);
    }

    @Test
    public void testDefaultProvidersOverride() {
        // The custom provider would be preferred over the internal FreemarkerLoginFormsProvider. Both has same order, so custom provider would be chosen (backwards compatibility with previous versions)
        testProviderImplementationClass(LoginFormsProvider.class, null, CustomLoginFormsProvider.class);

        // The provider with highest order is chosen
        testProviderImplementationClass(EmailSenderProvider.class, null, CustomDefaultEmailSenderProvider2.class);
    }

    private void testProviderImplementationClass(Class<? extends Provider> providerClass, String providerId, Class<? extends Provider> expectedProviderImplClass) {
        String providerImplClass = getTestingClient().testing().getProviderClassName(providerClass.getName(), providerId);
        Assert.assertEquals(expectedProviderImplClass.getName(), providerImplClass);
    }
}
