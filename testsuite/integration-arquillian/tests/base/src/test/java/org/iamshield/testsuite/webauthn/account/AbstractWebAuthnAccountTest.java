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
 */

package org.iamshield.testsuite.webauthn.account;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.After;
import org.junit.Before;
import org.iamshield.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.iamshield.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.iamshield.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticatorFactory;
import org.iamshield.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.iamshield.authentication.requiredactions.WebAuthnRegisterFactory;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.credential.WebAuthnCredentialModel;
import org.iamshield.representations.idm.AuthenticationExecutionRepresentation;
import org.iamshield.representations.idm.AuthenticationFlowRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.RequiredActionProviderSimpleRepresentation;
import org.iamshield.testsuite.AbstractAuthTest;
import org.iamshield.testsuite.page.AbstractPatternFlyAlert;
import org.iamshield.testsuite.webauthn.pages.SigningInPage;
import org.iamshield.testsuite.webauthn.utils.SigningInPageUtils;
import org.iamshield.testsuite.pages.DeleteCredentialPage;
import org.iamshield.testsuite.updaters.RealmAttributeUpdater;
import org.iamshield.testsuite.util.FlowUtil;
import org.iamshield.testsuite.webauthn.AbstractWebAuthnVirtualTest;
import org.iamshield.testsuite.webauthn.authenticators.DefaultVirtualAuthOptions;
import org.iamshield.testsuite.webauthn.authenticators.UseVirtualAuthenticators;
import org.iamshield.testsuite.webauthn.authenticators.VirtualAuthenticatorManager;
import org.iamshield.testsuite.webauthn.pages.WebAuthnErrorPage;
import org.iamshield.testsuite.webauthn.pages.WebAuthnLoginPage;
import org.iamshield.testsuite.webauthn.pages.WebAuthnRegisterPage;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticatorOptions;

import jakarta.ws.rs.ClientErrorException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.iamshield.models.AuthenticationExecutionModel.Requirement.REQUIRED;
import static org.iamshield.testsuite.admin.Users.setPasswordFor;
import static org.iamshield.testsuite.util.BrowserDriverUtil.isDriverFirefox;
import static org.iamshield.testsuite.util.WaitUtils.waitForPageToLoad;

public abstract class AbstractWebAuthnAccountTest extends AbstractAuthTest implements UseVirtualAuthenticators {

    @Page
    protected SigningInPage signingInPage;

    @Page
    protected WebAuthnRegisterPage webAuthnRegisterPage;

    @Page
    protected WebAuthnErrorPage webAuthnErrorPage;

    @Page
    protected WebAuthnLoginPage webAuthnLoginPage;

    @Page
    private DeleteCredentialPage deleteCredentialPage;

    private VirtualAuthenticatorManager webAuthnManager;
    protected SigningInPage.CredentialType webAuthnCredentialType;
    protected SigningInPage.CredentialType webAuthnPwdlessCredentialType;

    protected static final String WEBAUTHN_FLOW_ID = "75e2390e-f296-49e6-acf8-6d21071d7e10";
    protected static final String DEFAULT_FLOW = "browser";

    @Override
    @Before
    public void setUpVirtualAuthenticator() {
        if (!isDriverFirefox(driver)) {
            webAuthnManager = AbstractWebAuthnVirtualTest.createDefaultVirtualManager(driver, getDefaultOptions());
        }
    }

    @Override
    @After
    public void removeVirtualAuthenticator() {
        if (!isDriverFirefox(driver)) {
            webAuthnManager.removeAuthenticator();
        }
    }

    public VirtualAuthenticatorManager getVirtualAuthManager() {
        return webAuthnManager;
    }

    @Before
    public void navigateBeforeTest() {
        driver.manage().window().setSize(new Dimension(1920, 1080));

        RealmRepresentation realm = testRealmResource().toRepresentation();
        assertThat(realm, notNullValue());
        realm.setBrowserFlow(DEFAULT_FLOW);
        testRealmResource().update(realm);

        webAuthnCredentialType = signingInPage.getCredentialType(WebAuthnCredentialModel.TYPE_TWOFACTOR);
        webAuthnPwdlessCredentialType = signingInPage.getCredentialType(WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        final String password = generatePassword();
        setPasswordFor(testUser, password);
        createTestUserWithAdminClient(false, password);

        signingInPage.navigateTo();
        waitForPageToLoad();
        loginToAccount();
        signingInPage.assertCurrent();
    }

    @Override
    protected void afterAbstractIAMShieldTestRealmImport() {
        super.afterAbstractIAMShieldTestRealmImport();

        // configure WebAuthn
        // we can't do this during the realm import because we'd need to specify all built-in flows as well
        AuthenticationFlowRepresentation flow = new AuthenticationFlowRepresentation();
        flow.setId(WEBAUTHN_FLOW_ID);
        flow.setAlias("webauthn flow");
        flow.setProviderId("basic-flow");
        flow.setBuiltIn(false);
        flow.setTopLevel(true);
        testRealmResource().flows().createFlow(flow);

        AuthenticationExecutionRepresentation execution = new AuthenticationExecutionRepresentation();
        execution.setAuthenticator(WebAuthnAuthenticatorFactory.PROVIDER_ID);
        execution.setPriority(10);
        execution.setRequirement(REQUIRED.toString());
        execution.setParentFlow(WEBAUTHN_FLOW_ID);
        testRealmResource().flows().addExecution(execution);

        execution.setAuthenticator(WebAuthnPasswordlessAuthenticatorFactory.PROVIDER_ID);
        testRealmResource().flows().addExecution(execution);

        RequiredActionProviderSimpleRepresentation requiredAction = new RequiredActionProviderSimpleRepresentation();
        requiredAction.setProviderId(WebAuthnRegisterFactory.PROVIDER_ID);
        requiredAction.setName("blahblah");

        try {
            testRealmResource().flows().registerRequiredAction(requiredAction);
            requiredAction.setProviderId(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID);
            testRealmResource().flows().registerRequiredAction(requiredAction);
        } catch (ClientErrorException e) {
            assertThat(e.getResponse(), notNullValue());
            assertThat(e.getResponse().getStatus(), is(409));
        }
    }

    protected VirtualAuthenticatorManager getWebAuthnManager() {
        return webAuthnManager;
    }

    protected VirtualAuthenticatorOptions getDefaultOptions() {
        return DefaultVirtualAuthOptions.DEFAULT.getOptions();
    }

    protected void loginToAccount() {
        if (!loginPage.isCurrent()) {
            signingInPage.navigateTo();
            waitForPageToLoad();
        }
        loginPage.assertCurrent();
        loginPage.form().login(testUser);
        waitForPageToLoad();
    }

    protected void logout() {
        signingInPage.navigateTo();
        signingInPage.assertCurrent();
        signingInPage.header().clickLogoutBtn();
        waitForPageToLoad();
    }

    protected SigningInPage.UserCredential addWebAuthnCredential(String label) {
        return addWebAuthnCredential(label, false);
    }

    protected SigningInPage.UserCredential addWebAuthnCredential(String label, boolean passwordless) {
        SigningInPage.CredentialType credentialType = passwordless ? webAuthnPwdlessCredentialType : webAuthnCredentialType;

        AbstractPatternFlyAlert.waitUntilHidden();

        credentialType.clickSetUpLink();
        webAuthnRegisterPage.assertCurrent();
        webAuthnRegisterPage.clickRegister();
        webAuthnRegisterPage.registerWebAuthnCredential(label);
        waitForPageToLoad();
        signingInPage.assertCurrent();
        return getNewestUserCredential(credentialType);
    }

    protected void testRemoveCredential(SigningInPage.UserCredential userCredential) {
        AbstractPatternFlyAlert.waitUntilHidden();
        SigningInPageUtils.testRemoveCredential(signingInPage, deleteCredentialPage, userCredential);
    }

    protected SigningInPage.UserCredential getNewestUserCredential(SigningInPage.CredentialType credentialType) {
        return SigningInPageUtils.getNewestUserCredential(testUserResource(), credentialType);
    }

    protected void setUpWebAuthnFlow(String newFlowAlias) {
        setUpWebAuthnFlow(newFlowAlias, false);
    }

    protected void setUpWebAuthnFlow(String newFlowAlias, boolean passwordless) {
        final String providerID = passwordless ? WebAuthnPasswordlessAuthenticatorFactory.PROVIDER_ID : WebAuthnAuthenticatorFactory.PROVIDER_ID;

        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session).copyBrowserFlow(newFlowAlias));
        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session)
                .selectFlow(newFlowAlias)
                .inForms(forms -> forms
                        .clear()
                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, UsernamePasswordFormFactory.PROVIDER_ID)
                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, providerID)
                )
                .defineAsBrowserFlow() // Activate this new flow
        );
    }

    protected RealmAttributeUpdater setLocalesUpdater(String defaultLocale, String... supportedLocales) {
        RealmAttributeUpdater updater = new RealmAttributeUpdater(testRealmResource())
                .setDefaultLocale(defaultLocale)
                .setInternationalizationEnabled(true)
                .addSupportedLocale(defaultLocale);

        for (String locale : supportedLocales) {
            updater.addSupportedLocale(locale);
        }
        return updater;
    }
}
