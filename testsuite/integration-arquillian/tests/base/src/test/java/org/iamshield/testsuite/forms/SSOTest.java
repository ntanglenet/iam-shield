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
package org.iamshield.testsuite.forms;

import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.iamshield.events.Details;
import org.iamshield.events.EventType;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.PasswordCredentialModel;
import org.iamshield.representations.IDToken;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.AbstractChangeImportedUserPasswordsTest;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.drone.Different;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.pages.AppPage.RequestType;
import org.iamshield.testsuite.pages.LoginPage;
import org.iamshield.testsuite.pages.LoginPasswordUpdatePage;
import org.iamshield.testsuite.util.MutualTLSUtils;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;
import org.iamshield.testsuite.util.oauth.OAuthClient;
import org.openqa.selenium.WebDriver;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import jakarta.ws.rs.core.Response;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class SSOTest extends AbstractChangeImportedUserPasswordsTest {

    @Drone
    @Different
    protected WebDriver driver2;

    @Page
    protected AppPage appPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected LoginPasswordUpdatePage updatePasswordPage;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Test
    public void loginSuccess() {
        loginPage.open();
        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.parseLoginResponse().getCode());

        EventRepresentation loginEvent = events.expectLogin().assertEvent();
        String sessionId = loginEvent.getSessionId();

        IDToken idToken = sendTokenRequestAndGetIDToken(loginEvent);
        Assert.assertEquals("1", idToken.getAcr());
        Long authTime = idToken.getAuth_time();

        appPage.open();

        oauth.openLoginForm();

        assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        loginEvent = events.expectLogin().removeDetail(Details.USERNAME).client("test-app").assertEvent();
        String sessionId2 = loginEvent.getSessionId();

        assertEquals(sessionId, sessionId2);

        // acr is 0 as we authenticated through SSO cookie
        idToken = sendTokenRequestAndGetIDToken(loginEvent);
        Assert.assertEquals("0", idToken.getAcr());
        // auth time hasn't changed as we authenticated through SSO cookie
        Assert.assertEquals(authTime, idToken.getAuth_time());

        appPage.assertCurrent();

        // Expire session
        testingClient.testing().removeUserSession("test", sessionId);

        oauth.doLogin("test-user@localhost", getPassword("test-user@localhost"));

        String sessionId4 = events.expectLogin().assertEvent().getSessionId();
        assertNotEquals(sessionId, sessionId4);

        events.clear();
    }


    @Test
    public void multipleSessions() {
        loginPage.open();
        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.parseLoginResponse().getCode());

        EventRepresentation login1 = events.expectLogin().assertEvent();

        //OAuthClient oauth2 = new OAuthClient(driver2);
        OAuthClient oauth2 = oauth.newConfig().driver(driver2);

        oauth2.doLogin("test-user@localhost", getPassword("test-user@localhost"));

        EventRepresentation login2 = events.expectLogin().assertEvent();

        Assert.assertEquals(RequestType.AUTH_RESPONSE, RequestType.valueOf(driver2.getTitle()));
        Assert.assertNotNull(oauth2.parseLoginResponse().getCode());

        assertNotEquals(login1.getSessionId(), login2.getSessionId());

        AccessTokenResponse tokenResponse = sendTokenRequestAndGetResponse(login1);
        oauth.logoutForm().idTokenHint(tokenResponse.getIdToken()).withRedirect().open();
        events.expectLogout(login1.getSessionId()).assertEvent();

        oauth.openLoginForm();

        assertTrue(loginPage.isCurrent());

        oauth2.openLoginForm();

        events.expectLogin().session(login2.getSessionId()).removeDetail(Details.USERNAME).assertEvent();
        Assert.assertEquals(RequestType.AUTH_RESPONSE, RequestType.valueOf(driver2.getTitle()));
        Assert.assertNotNull(oauth2.parseLoginResponse().getCode());

        String code = oauth2.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth2.doAccessTokenRequest(code);
        events.poll();
        oauth2.logoutForm().idTokenHint(response.getIdToken()).withRedirect().open();
        events.expectLogout(login2.getSessionId()).assertEvent();

        oauth2.openLoginForm();

        assertTrue(driver2.getTitle().equals("Sign in to test"));
    }


    @Test
    public void loginWithRequiredActionAddedInTheMeantime() {
        // SSO login
        loginPage.open();
        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.parseLoginResponse().getCode());

        EventRepresentation loginEvent = events.expectLogin().assertEvent();
        String sessionId = loginEvent.getSessionId();

        // Add update-profile required action to user now
        UserRepresentation user = testRealm().users().get(loginEvent.getUserId()).toRepresentation();
        user.getRequiredActions().add(UserModel.RequiredAction.UPDATE_PASSWORD.toString());
        testRealm().users().get(loginEvent.getUserId()).update(user);

        // Attempt SSO login. update-password form is shown
        oauth.openLoginForm();
        updatePasswordPage.assertCurrent();

        updatePasswordPage.changePassword(getPassword("test-user@localhost"), getPassword("test-user@localhost"));
        events.expectRequiredAction(EventType.UPDATE_PASSWORD).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE).assertEvent();
        events.expectRequiredAction(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE).assertEvent();

        assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        loginEvent = events.expectLogin().removeDetail(Details.USERNAME).client("test-app").assertEvent();
        String sessionId2 = loginEvent.getSessionId();
        assertEquals(sessionId, sessionId2);


    }

    @Test
    public void failIfUsingCodeFromADifferentSession() throws IOException {
        // first client user login
        oauth.openLoginForm();
        oauth.doLogin("test-user@localhost", getPassword("test-user@localhost"));
        String firstCode = oauth.parseLoginResponse().getCode();

        // second client user login
        OAuthClient oauth2 = oauth.newConfig().driver(driver2);
        oauth2.doLogin("john-doh@localhost", getPassword("john-doh@localhost"));
        String secondCode = oauth2.parseLoginResponse().getCode();
        String[] firstCodeParts = firstCode.split("\\.");
        String[] secondCodeParts = secondCode.split("\\.");
        secondCodeParts[1] = firstCodeParts[1];
        secondCode = String.join(".", secondCodeParts);

        AccessTokenResponse tokenResponse;

        try (CloseableHttpClient client = MutualTLSUtils.newCloseableHttpClientWithOtherKeyStoreAndTrustStore()) {
            oauth.httpClient().set(client);
            tokenResponse = oauth2.doAccessTokenRequest(secondCode);
        } finally {
            oauth.httpClient().reset();
        }

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), tokenResponse.getStatusCode());
    }
}
