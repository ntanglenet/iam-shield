/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.testsuite.actions;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.iamshield.OAuth2Constants;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.authentication.authenticators.browser.UsernameFormFactory;
import org.iamshield.events.Details;
import org.iamshield.events.EventType;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.UserModel.RequiredAction;
import org.iamshield.models.credential.PasswordCredentialModel;
import org.iamshield.models.utils.DefaultAuthenticationFlows;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.representations.idm.UserSessionRepresentation;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.admin.ApiUtil;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.pages.AppPage.RequestType;
import org.iamshield.testsuite.pages.LoginPage;
import org.iamshield.testsuite.pages.LoginPasswordUpdatePage;
import org.iamshield.testsuite.pages.LoginUsernameOnlyPage;
import org.iamshield.testsuite.util.FlowUtil;
import org.iamshield.testsuite.util.GreenMailRule;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;
import org.iamshield.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.iamshield.testsuite.util.oauth.OAuthClient;
import org.iamshield.testsuite.util.RealmManager;
import org.iamshield.testsuite.util.SecondBrowser;
import org.openqa.selenium.WebDriver;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RequiredActionResetPasswordTest extends AbstractTestRealmIAMShieldTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        testRealm.setResetPasswordAllowed(Boolean.TRUE);
    }

    @Drone
    @SecondBrowser
    private WebDriver driver2;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Rule
    public GreenMailRule greenMail = new GreenMailRule();

    @Page
    protected AppPage appPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected LoginUsernameOnlyPage loginUsernameOnlyPage;

    @Page
    protected LoginPasswordUpdatePage changePasswordPage;

    @After
    public void after() {
        ApiUtil.resetUserPassword(testRealm().users().get(findUser("test-user@localhost").getId()), "password", false);
    }

    @Test
    public void tempPassword() throws Exception {
        requireUpdatePassword();
        loginPage.open();
        loginPage.login("test-user@localhost", "password");

        changePasswordPage.assertCurrent();
        assertFalse(changePasswordPage.isCancelDisplayed());

        changePasswordPage.changePassword("new-password", "new-password");

        events.expectRequiredAction(EventType.UPDATE_PASSWORD).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE).assertEvent();
        events.expectRequiredAction(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE).assertEvent();

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        EventRepresentation loginEvent = events.expectLogin().assertEvent();

        AccessTokenResponse tokenResponse = sendTokenRequestAndGetResponse(loginEvent);
        oauth.logoutForm().idTokenHint(tokenResponse.getIdToken()).withRedirect().open();

        events.expectLogout(loginEvent.getSessionId()).assertEvent();

        loginPage.open();
        loginPage.login("test-user@localhost", "new-password");

        events.expectLogin().assertEvent();
    }

    @Test
    public void resetPasswordLogoutSessionsChecked() {
        resetPassword(true);
    }

    @Test
    public void resetPasswordLogoutSessionsNotChecked() {
        resetPassword(false);
    }

    private void resetPassword(boolean logoutOtherSessions) {
        // create a regular session
        OAuthClient oauth2 = oauth.newConfig().driver(driver2);
        UserResource testUser = testRealm().users().get(findUser("test-user@localhost").getId());
        oauth2.doLogin("test-user@localhost", "password");
        EventRepresentation regularSession = events.expectLogin().assertEvent();
        assertEquals(1, testUser.getUserSessions().size());

        // navigate to a neutral URL to then clear the cookies on that domain
        oauth2.getDriver().navigate().to(oauth2.getEndpoints().getJwks());
        oauth2.getDriver().manage().deleteAllCookies();

        // create an offline session
        oauth2.scope(OAuth2Constants.OFFLINE_ACCESS);
        AuthorizationEndpointResponse os = oauth2.doLogin("test-user@localhost", "password");
        EventRepresentation offlineSession = events.expectLogin().assertEvent();
        AccessTokenResponse at = oauth2.doAccessTokenRequest(os.getCode());
        String clientUuid = testRealm().clients().findByClientId(oauth2.getClientId()).get(0).getId();
        assertEquals(1, testUser.getOfflineSessions(clientUuid).size());

        requireUpdatePassword();

        loginPage.open();
        loginPage.login("test-user@localhost", "password");
        changePasswordPage.assertCurrent();
        assertTrue(changePasswordPage.isLogoutSessionDisplayed());
        assertFalse(changePasswordPage.isLogoutSessionsChecked());
        if (logoutOtherSessions) {
            changePasswordPage.checkLogoutSessions();
        }
        changePasswordPage.changePassword("All Right Then, Keep Your Secrets", "All Right Then, Keep Your Secrets");

        if (logoutOtherSessions) {
            events.expectLogout(regularSession.getSessionId())
                    .detail(Details.LOGOUT_TRIGGERED_BY_REQUIRED_ACTION, RequiredAction.UPDATE_PASSWORD.name())
                    .assertEvent(true);
            events.expectLogout(offlineSession.getSessionId())
                    .detail(Details.LOGOUT_TRIGGERED_BY_REQUIRED_ACTION, RequiredAction.UPDATE_PASSWORD.name())
                    .assertEvent();
        }

        events.expectRequiredAction(EventType.UPDATE_PASSWORD).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE).assertEvent(true);
        events.expectRequiredAction(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE).assertEvent();

        EventRepresentation event2 = events.expectLogin().assertEvent();
        List<UserSessionRepresentation> regularSessions = testUser.getUserSessions();
        List<UserSessionRepresentation> offlineSessions = testUser.getOfflineSessions(clientUuid);
        if (logoutOtherSessions) {
            assertEquals(1, regularSessions.size());
            assertEquals(event2.getSessionId(), regularSessions.iterator().next().getId());
            assertEquals(0, offlineSessions.size());
        } else {
            assertEquals(2, regularSessions.size());
            MatcherAssert.assertThat(regularSessions.stream().map(UserSessionRepresentation::getId).collect(Collectors.toList()),
                    Matchers.containsInAnyOrder(regularSession.getSessionId(), event2.getSessionId()));
            MatcherAssert.assertThat(offlineSessions.stream().map(UserSessionRepresentation::getId).collect(Collectors.toList()),
                    Matchers.containsInAnyOrder(offlineSession.getSessionId()));
        }
    }

    @Test
    public void resetPasswordActionNotTriggered() {
        String newFlowAlias = "browser - username only";

        try {
            RealmManager.realm(testRealm()).passwordPolicy("forceExpiredPasswordChange(1)");
            setTimeOffset(60 * 60 * 48);

            //create username only flow
            testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session).copyBrowserFlow(newFlowAlias));
            testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session)
                    .selectFlow(newFlowAlias)
                    .clear()
                    .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
                    .defineAsBrowserFlow() // Activate this new flow
            );
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("test-user@localhost");
            events.expectLogin().assertEvent();
        } finally {
            //reset browser flow and delete username only flow
            RealmRepresentation realm = testRealm().toRepresentation();
            realm.setBrowserFlow(DefaultAuthenticationFlows.BROWSER_FLOW);
            testRealm().update(realm);

            testRealm().flows()
                    .getFlows()
                    .stream()
                    .filter(flowRep -> flowRep.getAlias().equals(newFlowAlias))
                    .findFirst()
                    .ifPresent(authenticationFlowRepresentation ->
                            testRealm().flows().deleteFlow(authenticationFlowRepresentation.getId()));

            setTimeOffset(0);
            RealmManager.realm(testRealm()).passwordPolicy(null);
        }
    }

    private void requireUpdatePassword() {
        UserRepresentation userRep = findUser("test-user@localhost");
        if (userRep.getRequiredActions() == null) {
            userRep.setRequiredActions(new LinkedList<>());
        }
        userRep.getRequiredActions().add(RequiredAction.UPDATE_PASSWORD.name());
        testRealm().users().get(userRep.getId()).update(userRep);
    }

}
