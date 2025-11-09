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

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.iamshield.OAuth2Constants;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.events.Details;
import org.iamshield.models.Constants;
import org.iamshield.models.credential.OTPCredentialModel;
import org.iamshield.models.credential.OTPCredentialModel.SecretEncoding;
import org.iamshield.models.credential.dto.OTPCredentialData;
import org.iamshield.models.credential.dto.OTPSecretData;
import org.iamshield.models.utils.Base32;
import org.iamshield.models.utils.TimeBasedOTP;
import org.iamshield.representations.idm.CredentialRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.AbstractChangeImportedUserPasswordsTest;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.pages.AppPage.RequestType;
import org.iamshield.testsuite.pages.LoginPage;
import org.iamshield.testsuite.pages.LoginTotpPage;
import org.iamshield.testsuite.updaters.RealmAttributeUpdater;
import org.iamshield.testsuite.util.AdminClientUtil;
import org.iamshield.testsuite.util.GreenMailRule;
import org.iamshield.testsuite.util.oauth.OAuthClient;
import org.iamshield.testsuite.util.RealmRepUtil;
import org.iamshield.testsuite.util.UserBuilder;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;
import org.iamshield.util.JsonSerialization;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;

import static org.iamshield.testsuite.auth.page.AuthRealm.TEST;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class LoginTotpTest extends AbstractChangeImportedUserPasswordsTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        super.configureTestRealm(testRealm);
        UserRepresentation user = RealmRepUtil.findUser(testRealm, "test-user@localhost");
        UserBuilder.edit(user)
                   .totpSecret("totpSecret")
                   .otpEnabled();
    }

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Rule
    public GreenMailRule greenMail = new GreenMailRule();

    @Page
    protected AppPage appPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected LoginTotpPage loginTotpPage;

    private TimeBasedOTP totp = new TimeBasedOTP();

    private int lifespan;

    @Before
    public void before() throws MalformedURLException {
        totp = new TimeBasedOTP();
    }

    @Test
    public void loginWithTotpFailure() throws Exception {
        loginPage.open();
        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        Assert.assertTrue(loginTotpPage.isCurrent());

        loginTotpPage.login("123456");
        loginTotpPage.assertCurrent();
        Assert.assertEquals("Invalid authenticator code.", loginTotpPage.getInputError());

        //loginPage.assertCurrent();  // Invalid authenticator code.
        //Assert.assertEquals("Invalid username or password.", loginPage.getError());

        events.expectLogin().error("invalid_user_credentials").session((String) null)
                .removeDetail(Details.CONSENT)
                .assertEvent();
    }

    @Test
    public void loginWithMissingTotp() throws Exception {
        loginPage.open();
        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        Assert.assertTrue(loginTotpPage.isCurrent());

        loginTotpPage.login(null);
        loginTotpPage.assertCurrent();
        Assert.assertEquals("Invalid authenticator code.", loginTotpPage.getInputError());

        //loginPage.assertCurrent();  // Invalid authenticator code.
        //Assert.assertEquals("Invalid username or password.", loginPage.getError());

        events.expectLogin().error("invalid_user_credentials").session((String) null)
                .removeDetail(Details.CONSENT)
                .assertEvent();
    }

    @Test
    public void loginWithTotpSuccess() throws Exception {
        loginPage.open();
        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        Assert.assertTrue(loginTotpPage.isCurrent());

        setOtpTimeOffset(TimeBasedOTP.DEFAULT_INTERVAL_SECONDS, totp);

        loginTotpPage.login(totp.generateTOTP("totpSecret"));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        events.expectLogin().assertEvent();
    }

    // KEYCLOAK-3835
    @Test
    public void loginWithTotpRefreshTotpPage() throws Exception {
        loginPage.open();
        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        Assert.assertTrue(loginTotpPage.isCurrent());

        // Refresh TOTP page
        driver.navigate().refresh();

        System.out.println(driver.getPageSource());

        loginTotpPage.login(totp.generateTOTP("totpSecret"));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        events.expectLogin().assertEvent();
    }

    @Test
    public void loginWithTotpInvalidPassword() throws Exception {
        loginPage.open();
        loginPage.login("test-user@localhost", "invalid");

        Assert.assertTrue(loginPage.isCurrent());

        Assert.assertEquals("Invalid username or password.", loginPage.getInputError());

        events.expectLogin().error("invalid_user_credentials").session((String) null)
                .removeDetail(Details.CONSENT)
                .assertEvent();
    }


    @Test
    public void loginWithTotp_testAttemptedUsernameAndResetLogin() throws Exception {
        loginPage.open();

        // Assert attempted-username NOT available
        loginPage.assertAttemptedUsernameAvailability(false);

        loginPage.login("test-user@localhost", getPassword("test-user@localhost"));

        Assert.assertTrue(loginTotpPage.isCurrent());

        // Assert attempted-username available
        loginPage.assertAttemptedUsernameAvailability(true);
        Assert.assertEquals("test-user@localhost", loginPage.getAttemptedUsername());

        // Reset login and assert back on the login screen
        loginTotpPage.clickResetLogin();

        loginPage.assertCurrent();
    }

    //KEYCLOAK-12908
    @Test
    public void loginWithTotp_getToken_checkCompatibilityCLI() throws IOException {
        Client httpClient = AdminClientUtil.createResteasyClient();
        try (RealmAttributeUpdater rau = new RealmAttributeUpdater(testRealm()).setOtpPolicyCodeReusable(true).update()) {
            WebTarget exchangeUrl = httpClient.target(OAuthClient.AUTH_SERVER_ROOT)
                    .path("/realms")
                    .path(TEST)
                    .path("protocol/openid-connect/token");

            Form form = new Form()
                    .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD)
                    .param(OAuth2Constants.USERNAME, "test-user@localhost")
                    .param(OAuth2Constants.PASSWORD, getPassword("test-user@localhost"))
                    .param(OAuth2Constants.CLIENT_ID, Constants.ADMIN_CLI_CLIENT_ID);

            // Compatibility between "otp" and "totp"
            Response response = exchangeUrl.request()
                    .post(Entity.form(form.param("otp", totp.generateTOTP("totpSecret"))));

            Assert.assertEquals(200, response.getStatus());
            response.close();

            response = exchangeUrl.request()
                    .post(Entity.form(form.param("totp", totp.generateTOTP("totpSecret"))));

            Assert.assertEquals(200, response.getStatus());
            response.close();

        } finally {
            httpClient.close();
        }
    }

    @Test
    public void testBase32EncodedSecret() throws IOException {
        UserRepresentation userRep = testRealm().users().search("test-user@localhost").get(0);
        UserResource user = testRealm().users().get(userRep.getId());
        List<CredentialRepresentation> credentials = user.credentials();
        CredentialRepresentation otpCredential = credentials.stream()
                .filter(c -> OTPCredentialModel.TYPE.equals(c.getType()))
                .findAny().orElse(null);

        Assert.assertNotNull(otpCredential);

        OTPCredentialData credentialData = JsonSerialization.readValue(otpCredential.getCredentialData(), OTPCredentialData.class);
        OTPCredentialData newCredentialData = new OTPCredentialData(credentialData.getSubType(), credentialData.getDigits(), credentialData.getCounter(), credentialData.getPeriod(), credentialData.getAlgorithm(),
                SecretEncoding.BASE32.name());
        UserRepresentation newUser = UserBuilder.create().username("test-otp-user@localhost").password(generatePassword("test-otp-user@localhost")).enabled(true).build();
        CredentialRepresentation credential = new CredentialRepresentation();

        credential.setType(otpCredential.getType());
        credential.setTemporary(false);
        credential.setUserLabel("my-otp");
        credential.setCredentialData(JsonSerialization.writeValueAsString(newCredentialData));

        String rawSecret = "JXGDDKNLXTBKGTA2KV6QJGAF4SS4R75X";

        credential.setSecretData(JsonSerialization.writeValueAsString(new OTPSecretData(rawSecret)));

        newUser.getCredentials().add(credential);

        testRealm().users().create(newUser).close();

        loginPage.open();
        loginPage.login(newUser.getUsername(), getPassword("test-otp-user@localhost"));

        Assert.assertTrue(loginTotpPage.isCurrent());

        setOtpTimeOffset(TimeBasedOTP.DEFAULT_INTERVAL_SECONDS, totp);

        loginTotpPage.login(totp.generateTOTP(Base32.decode(rawSecret)));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());
    }
}
