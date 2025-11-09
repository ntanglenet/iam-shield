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
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.iamshield.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.iamshield.common.Profile;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.events.EventType;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.representations.idm.AuthenticationExecutionRepresentation;
import org.iamshield.representations.idm.AuthenticationFlowRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.ProfileAssume;
import org.iamshield.testsuite.arquillian.annotation.EnableFeature;
import org.iamshield.testsuite.pages.LoginPage;
import org.iamshield.testsuite.util.ExecutionBuilder;
import org.iamshield.testsuite.util.FlowBuilder;
import org.iamshield.testsuite.util.RealmBuilder;
import org.iamshield.testsuite.util.UserBuilder;

import jakarta.ws.rs.core.Response;

import java.util.UUID;

import static org.iamshield.common.Profile.Feature.AUTHORIZATION;

/**
 * Tests for {@link org.iamshield.authentication.authenticators.browser.ScriptBasedAuthenticator}
 *
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
@EnableFeature(value = Profile.Feature.SCRIPTS)
public class ScriptAuthenticatorTest extends AbstractFlowTest {

    @Page
    protected LoginPage loginPage;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    private AuthenticationFlowRepresentation flow;
    private static String userId;
    private static String failId;

    public static final String EXECUTION_ID = "scriptAuth";

    @BeforeClass
    public static void enabled() {
        ProfileAssume.assumeFeatureEnabled(AUTHORIZATION);
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        super.configureTestRealm(testRealm);
        UserRepresentation failUser = UserBuilder.create()
                .id(UUID.randomUUID().toString())
                .username("fail")
                .email("fail@test.com")
                .enabled(true)
                .password(generatePassword("fail"))
                .build();

        UserRepresentation okayUser = UserBuilder.create()
                .id(UUID.randomUUID().toString())
                .username("user")
                .email("user@test.com")
                .enabled(true)
                .password(generatePassword("user"))
                .build();

        RealmBuilder.edit(testRealm)
                .user(failUser)
                .user(okayUser);
    }

    @Override
    public void importTestRealms() {
        super.importTestRealms();
        userId = adminClient.realm("test").users().search("user", true).get(0).getId();
        failId = adminClient.realm("test").users().search("fail", true).get(0).getId();
    }

    @Before
    public void configureFlows() throws Exception {
        String scriptFlow = "scriptBrowser";

        if (testContext.isInitialized()) {
            this.flow = findFlowByAlias(scriptFlow);
            return;
        }

        AuthenticationFlowRepresentation scriptBrowserFlow = FlowBuilder.create()
                .alias(scriptFlow)
                .description("dummy pass through registration")
                .providerId("basic-flow")
                .topLevel(true)
                .builtIn(false)
                .build();

        Response createFlowResponse = testRealm().flows().createFlow(scriptBrowserFlow);
        Assert.assertEquals(201, createFlowResponse.getStatus());

        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setBrowserFlow(scriptFlow);
        realm.setDirectGrantFlow(scriptFlow);
        testRealm().update(realm);

        this.flow = findFlowByAlias(scriptFlow);

        AuthenticationExecutionRepresentation usernamePasswordFormExecution = ExecutionBuilder.create()
                .id("username password form")
                .parentFlow(this.flow.getId())
                .requirement(AuthenticationExecutionModel.Requirement.REQUIRED.name())
                .authenticator(UsernamePasswordFormFactory.PROVIDER_ID)
                .build();

        AuthenticationExecutionRepresentation authScriptExecution = ExecutionBuilder.create()
                .id(EXECUTION_ID)
                .parentFlow(this.flow.getId())
                .requirement(AuthenticationExecutionModel.Requirement.REQUIRED.name())
                .authenticator("script-scripts/auth-example.js")
                .build();

        Response addExecutionResponse = testRealm().flows().addExecution(usernamePasswordFormExecution);
        Assert.assertEquals(201, addExecutionResponse.getStatus());
        addExecutionResponse.close();

        addExecutionResponse = testRealm().flows().addExecution(authScriptExecution);
        Assert.assertEquals(201, addExecutionResponse.getStatus());
        addExecutionResponse.close();

        testContext.setInitialized(true);
    }

    /**
     * KEYCLOAK-3491
     */
    @Test
    public void loginShouldWorkWithScriptAuthenticator() {
        loginPage.open();

        loginPage.login("user", getPassword("user"));

        events.expectLogin().user(userId).detail(Details.USERNAME, "user").assertEvent();
    }

    /**
     * KEYCLOAK-3491
     */
    @Test
    public void loginShouldFailWithScriptAuthenticator() {
        loginPage.open();

        loginPage.login("fail", getPassword("fail"));

        events.expect(EventType.LOGIN_ERROR).user((String) null).error(Errors.USER_NOT_FOUND).assertEvent();
    }

    /**
     * KEYCLOAK-4505
     */
    @Test
    public void scriptWithClientSession()  {
        AuthenticationExecutionRepresentation authScriptExecution = ExecutionBuilder.create()
                .id(EXECUTION_ID + "client-session")
                .parentFlow(this.flow.getId())
                .requirement(AuthenticationExecutionModel.Requirement.REQUIRED.name())
                .authenticator("script-scripts/auth-session.js")
                .build();

        Response addExecutionResponse = testRealm().flows().addExecution(authScriptExecution);
        Assert.assertEquals(201, addExecutionResponse.getStatus());
        addExecutionResponse.close();

        loginPage.open();

        loginPage.login("user", getPassword("user"));

        events.expectLogin().user(userId).detail(Details.USERNAME, "user").assertEvent();
    }
}

