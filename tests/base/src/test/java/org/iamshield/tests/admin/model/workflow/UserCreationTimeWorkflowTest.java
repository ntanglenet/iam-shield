package org.iamshield.tests.admin.model.workflow;

import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.iamshield.common.util.Time;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.workflow.DisableUserStepProviderFactory;
import org.iamshield.models.workflow.NotifyUserStepProviderFactory;
import org.iamshield.models.workflow.WorkflowsManager;
import org.iamshield.models.workflow.UserCreationTimeWorkflowProviderFactory;
import org.iamshield.representations.idm.CredentialRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.representations.workflows.WorkflowStepRepresentation;
import org.iamshield.representations.workflows.WorkflowRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.mail.MailServer;
import org.iamshield.testframework.mail.annotations.InjectMailServer;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.ui.annotations.InjectPage;
import org.iamshield.testframework.ui.annotations.InjectWebDriver;
import org.iamshield.testframework.ui.page.LoginPage;
import org.openqa.selenium.WebDriver;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.iamshield.tests.admin.model.workflow.WorkflowManagementTest.findEmailByRecipient;

@IAMShieldIntegrationTest(config = WorkflowsServerConfig.class)
public class UserCreationTimeWorkflowTest {

    private static final String REALM_NAME = "default";

    @InjectRunOnServer(permittedPackages = "org.iamshield.tests")
    RunOnServerClient runOnServer;

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

    @Test
    public void testDisableUserBasedOnCreationDate() {
        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .withSteps(
                        WorkflowStepRepresentation.create().of(NotifyUserStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .build(),
                        WorkflowStepRepresentation.create().of(DisableUserStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .build()
                ).build()).close();

        // create a new user - this will trigger the association with the workflow
        managedRealm.admin().users().create(
                this.getUserRepresentation("alice", "Alice", "Wonderland", "alice@wornderland.org")).close();

        // test running the scheduled steps
        runOnServer.run((session -> {
            RealmModel realm = configureSessionContext(session);
            WorkflowsManager manager = new WorkflowsManager(session);

            UserModel user = session.users().getUserByUsername(realm, "alice");
            assertTrue(user.isEnabled());
            assertNull(user.getAttributes().get("message"));

            // running the scheduled tasks now shouldn't pick up any step as none are due to run yet
            manager.runScheduledSteps();
            user = session.users().getUserByUsername(realm, "alice");
            assertTrue(user.isEnabled());
            assertNull(user.getAttributes().get("message"));

            try {
                // set offset to 7 days - notify step should run now
                Time.setOffset(Math.toIntExact(Duration.ofDays(6).toSeconds()));
                manager.runScheduledSteps();
                user = session.users().getUserByUsername(realm, "alice");
                assertTrue(user.isEnabled());
            } finally {
                Time.setOffset(0);
            }
        }));

        // Verify that the notify step was executed by checking email was sent
        MimeMessage testUserMessage = findEmailByRecipient(mailServer, "alice@wornderland.org");
        assertNotNull(testUserMessage, "The first step (notify) should have sent an email.");

        mailServer.runCleanup();

        // logging-in with alice should not reset the workflow - we should still run the disable step next
        oauth.openLoginForm();
        loginPage.fillLogin("alice", "alice");
        loginPage.submit();
        assertTrue(driver.getPageSource().contains("Happy days"));

        // test running the scheduled steps
        runOnServer.run((session -> {
            RealmModel realm = configureSessionContext(session);
            WorkflowsManager manager = new WorkflowsManager(session);

            try {
                // set offset to 11 days - disable step should run now
                Time.setOffset(Math.toIntExact(Duration.ofDays(12).toSeconds()));
                manager.runScheduledSteps();
                UserModel user = session.users().getUserByUsername(realm, "alice");
                assertFalse(user.isEnabled());
            } finally {
                Time.setOffset(0);
            }
        }));
    }

    private static RealmModel configureSessionContext(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        session.getContext().setRealm(realm);
        return realm;
    }

    private UserRepresentation getUserRepresentation(String username, String firstName, String lastName, String email) {
        UserRepresentation representation = new UserRepresentation();
        representation.setUsername(username);
        representation.setFirstName(firstName);
        representation.setLastName(lastName);
        representation.setEmail(email);
        representation.setEnabled(true);
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(username);
        representation.setCredentials(List.of(credential));
        return representation;
    }
}
