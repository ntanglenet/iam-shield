/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.tests.admin.model.workflow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.iamshield.tests.admin.model.workflow.WorkflowManagementTest.findEmailByRecipient;
import static org.iamshield.tests.admin.model.workflow.WorkflowManagementTest.findEmailsByRecipient;
import static org.iamshield.tests.admin.model.workflow.WorkflowManagementTest.verifyEmailContent;

import java.time.Duration;
import java.util.List;

import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.iamshield.common.util.Time;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserProvider;
import org.iamshield.models.workflow.DisableUserStepProviderFactory;
import org.iamshield.models.workflow.NotifyUserStepProviderFactory;
import org.iamshield.models.workflow.ResourceOperationType;
import org.iamshield.models.workflow.WorkflowsManager;
import org.iamshield.models.workflow.UserSessionRefreshTimeWorkflowProviderFactory;
import org.iamshield.representations.workflows.WorkflowStepRepresentation;
import org.iamshield.representations.workflows.WorkflowRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.InjectUser;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.mail.MailServer;
import org.iamshield.testframework.mail.annotations.InjectMailServer;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.ManagedUser;
import org.iamshield.testframework.realm.UserConfig;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.ui.annotations.InjectPage;
import org.iamshield.testframework.ui.annotations.InjectWebDriver;
import org.iamshield.testframework.ui.page.LoginPage;
import org.openqa.selenium.WebDriver;

@IAMShieldIntegrationTest(config = WorkflowsServerConfig.class)
public class UserSessionRefreshTimeWorkflowTest {

    private static final String REALM_NAME = "default";

    @InjectRunOnServer(permittedPackages = "org.iamshield.tests")
    RunOnServerClient runOnServer;

    @InjectUser(ref = "alice", config = DefaultUserConfig.class, lifecycle = LifeCycle.METHOD)
    private ManagedUser userAlice;

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectWebDriver
    WebDriver driver;

    @InjectPage
    LoginPage loginPage;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectMailServer
    private MailServer mailServer;

    @BeforeEach
    public void onBefore() {
        oauth.realm("default");

        runOnServer.run(session -> {
            WorkflowsManager manager = new WorkflowsManager(session);
            manager.removeWorkflows();
        });
    }

    @Test
    public void testDisabledUserAfterInactivityPeriod() {
        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserSessionRefreshTimeWorkflowProviderFactory.ID)
                .onEvent(ResourceOperationType.USER_LOGIN.toString())
                .withSteps(
                        WorkflowStepRepresentation.create().of(NotifyUserStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .build(),
                        WorkflowStepRepresentation.create().of(DisableUserStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .build()
                ).build()).close();

        // login with alice - this will attach the workflow to the user and schedule the first step
        oauth.openLoginForm();
        String username = userAlice.getUsername();
        loginPage.fillLogin(username, userAlice.getPassword());
        loginPage.submit();
        assertTrue(driver.getPageSource() != null && driver.getPageSource().contains("Happy days"));

        // test running the scheduled steps
        runOnServer.run((session -> {
            RealmModel realm = configureSessionContext(session);
            WorkflowsManager manager = new WorkflowsManager(session);

            UserModel user = session.users().getUserByUsername(realm, username);
            assertTrue(user.isEnabled());

            // running the scheduled tasks now shouldn't pick up any step as none are due to run yet
            manager.runScheduledSteps();
            user = session.users().getUserByUsername(realm, username);
            assertTrue(user.isEnabled());

            try {
                // set offset to 6 days - notify step should run now
                Time.setOffset(Math.toIntExact(Duration.ofDays(5).toSeconds()));
                manager.runScheduledSteps();
                user = session.users().getUserByUsername(realm, username);
                assertTrue(user.isEnabled());
            } finally {
                Time.setOffset(0);
            }
        }));

        // Verify that the notify step was executed by checking email was sent
        MimeMessage testUserMessage = findEmailByRecipient(mailServer, "master-admin@email.org");
        assertNotNull(testUserMessage, "The first step (notify) should have sent an email.");

        mailServer.runCleanup();

        // trigger a login event that should reset the flow of the workflow
        oauth.openLoginForm();

        runOnServer.run((session -> {
            try {
                // setting the offset to 11 days should not run the second step as we re-started the flow on login
                RealmModel realm = configureSessionContext(session);
                Time.setOffset(Math.toIntExact(Duration.ofDays(11).toSeconds()));
                WorkflowsManager manager = new WorkflowsManager(session);
                manager.runScheduledSteps();
                UserModel user = session.users().getUserByUsername(realm, username);
                assertTrue(user.isEnabled());
            } finally {
                Time.setOffset(0);
            }

            try {
                // first step has run and the next step should be triggered after 5 more days (time difference between the steps)
                RealmModel realm = configureSessionContext(session);
                Time.setOffset(Math.toIntExact(Duration.ofDays(17).toSeconds()));
                WorkflowsManager manager = new WorkflowsManager(session);
                manager.runScheduledSteps();
                UserModel user = session.users().getUserByUsername(realm, username);
                // second step should have run and the user should be disabled now
                assertFalse(user.isEnabled());
            } finally {
                Time.setOffset(0);
            }
        }));
    }

    @Test
    public void testMultipleWorkflows() {
        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserSessionRefreshTimeWorkflowProviderFactory.ID)
                .onEvent(ResourceOperationType.USER_LOGIN.toString())
                .withSteps(
                        WorkflowStepRepresentation.create().of(NotifyUserStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .withConfig("custom_subject_key", "notifier1_subject")
                                .withConfig("custom_message", "notifier1_message")
                                .build()
                ).of(UserSessionRefreshTimeWorkflowProviderFactory.ID)
                .onEvent(ResourceOperationType.USER_LOGIN.toString())
                .withSteps(
                        WorkflowStepRepresentation.create().of(NotifyUserStepProviderFactory.ID)
                                .after(Duration.ofDays(10))
                                .withConfig("custom_subject_key", "notifier2_subject")
                                .withConfig("custom_message", "notifier2_message")
                                .build())
                .build()).close();

        // perform a login to associate the workflows with the new user.
        oauth.openLoginForm();
        String username = userAlice.getUsername();
        loginPage.fillLogin(username, userAlice.getPassword());
        loginPage.submit();
        assertTrue(driver.getPageSource() != null && driver.getPageSource().contains("Happy days"));

        runOnServer.run(session -> {
            RealmModel realm = configureSessionContext(session);
            WorkflowsManager manager = new WorkflowsManager(session);

            UserProvider users = session.users();
            UserModel user = users.getUserByUsername(realm, username);
            assertTrue(user.isEnabled());

            try {
                Time.setOffset(Math.toIntExact(Duration.ofDays(7).toSeconds()));
                manager.runScheduledSteps();
                user = users.getUserByUsername(realm, username);
                assertTrue(user.isEnabled());
            } finally {
                Time.setOffset(0);
            }
        });

        // Verify that the first notify step was executed by checking email was sent
        List<MimeMessage> testUserMessages = findEmailsByRecipient(mailServer, "master-admin@email.org");
        // Only one notify message should be sent
        assertEquals(1, testUserMessages.size());
        assertNotNull(testUserMessages.get(0), "The first step (notify) should have sent an email.");
        verifyEmailContent(testUserMessages.get(0), "master-admin@email.org", "notifier1_subject", "notifier1_message");

        mailServer.runCleanup();

        runOnServer.run(session -> {
            RealmModel realm = configureSessionContext(session);
            WorkflowsManager manager = new WorkflowsManager(session);

            UserModel user = session.users().getUserByUsername(realm, username);
            try {
                Time.setOffset(Math.toIntExact(Duration.ofDays(11).toSeconds()));
                manager.runScheduledSteps();
                user = session.users().getUserByUsername(realm, username);
                assertTrue(user.isEnabled());
            } finally {
                Time.setOffset(0);
            }
        });

        // Verify that the second notify step was executed by checking email was sent
        testUserMessages = findEmailsByRecipient(mailServer, "master-admin@email.org");
        // Only one notify message should be sent
        assertEquals(1, testUserMessages.size());
        assertNotNull(testUserMessages.get(0), "The second step (notify) should have sent an email.");
        verifyEmailContent(testUserMessages.get(0), "master-admin@email.org", "notifier2_subject", "notifier2_message");
    }

    private static RealmModel configureSessionContext(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        session.getContext().setRealm(realm);
        return realm;
    }

    private static class DefaultUserConfig implements UserConfig {

        @Override
        public UserConfigBuilder configure(UserConfigBuilder user) {
            user.username("alice");
            user.password("alice");
            user.name("alice", "alice");
            user.email("master-admin@email.org");
            return user;
        }
    }
}
