/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.iamshield.testsuite.forms;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.iamshield.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.iamshield.authentication.authenticators.resetcred.ResetCredentialEmail;
import org.iamshield.authentication.authenticators.resetcred.ResetPassword;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.utils.DefaultAuthenticationFlows;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.admin.ApiUtil;
import org.iamshield.testsuite.client.IAMShieldTestingClient;
import org.iamshield.testsuite.pages.LoginPage;
import org.iamshield.testsuite.pages.LoginPasswordResetPage;
import org.iamshield.testsuite.pages.LoginUsernameOnlyPage;
import org.iamshield.testsuite.util.FlowUtil;
import org.iamshield.testsuite.util.GreenMailRule;
import org.iamshield.testsuite.util.UserBuilder;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.iamshield.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * Tests setting up alternative reset credentials sub flow to prevent signing in after clicking "forgot password"
 *
 * @author <a href="mailto:drichtar@redhat.com">Denis Richtárik</a>
 */
public class AltSubflowForCredentialResetTest extends AbstractTestRealmIAMShieldTest {

    private String userID;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Rule
    public GreenMailRule greenMailRule = new GreenMailRule();

    @Page
    LoginPage loginPage;

    @Page
    protected LoginUsernameOnlyPage loginUsernameOnlyPage;

    @Page
    LoginPasswordResetPage loginPasswordResetPage;

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    private RealmRepresentation loadTestRealm() {
        RealmRepresentation res = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        res.setResetCredentialsFlow(DefaultAuthenticationFlows.RESET_CREDENTIALS_FLOW);
        return res;
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        log.debug("Adding test realm for import from testrealm.json");
        testRealms.add(loadTestRealm());
    }

    @Before
    public void setup() {
        log.info("Adding login-test user");
        UserRepresentation testUser = UserBuilder.create().username("login-test").email("login@test.com").enabled(true).build();

        userID = ApiUtil.createUserAndResetPasswordWithAdminClient(testRealm(), testUser, "password");
        getCleanup().addUserId(userID);
    }

    private void configureAlternativeResetCredentialsFlow() {
        configureAlternativeResetCredentialsFlow(testingClient);
    }

    static void configureAlternativeResetCredentialsFlow(IAMShieldTestingClient testingClient) {
        final String newFlowAlias = DefaultAuthenticationFlows.RESET_CREDENTIALS_FLOW + " - alternative";
        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session).copyResetCredentialsFlow(newFlowAlias));
        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session).selectFlow(newFlowAlias)
                .clear()
                .addSubFlowExecution(AuthenticationExecutionModel.Requirement.ALTERNATIVE, altSubFlow -> altSubFlow
                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, ResetCredentialChooseUser.PROVIDER_ID)
                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, ResetCredentialEmail.PROVIDER_ID)
                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, ResetPassword.PROVIDER_ID))
                .defineAsResetCredentialsFlow());
    }

    @Test
    public void alternativeSubflowStaySignedOutTest() {
        configureAlternativeResetCredentialsFlow();
        try {
            loginPage.open();
            loginPage.resetPassword();
            Assert.assertTrue(loginPasswordResetPage.isCurrent());
            loginPasswordResetPage.changePassword("login@test.com.com");
            Assert.assertTrue(loginPage.isCurrent());
            assertEquals("You should receive an email shortly with further instructions.", loginUsernameOnlyPage.getSuccessMessage());
            loginPage.open();
            Assert.assertTrue(loginPage.isCurrent());
        } finally {
            testRealm().flows().getFlows().clear();
            RealmRepresentation realm = testRealm().toRepresentation();
            realm.setResetCredentialsFlow(DefaultAuthenticationFlows.RESET_CREDENTIALS_FLOW);
            testRealm().update(realm);
        }
    }
}
