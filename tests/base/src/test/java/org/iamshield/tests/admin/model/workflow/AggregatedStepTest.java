package org.iamshield.tests.admin.model.workflow;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.junit.jupiter.api.Test;
import org.iamshield.common.util.Time;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.workflow.AggregatedStepProviderFactory;
import org.iamshield.models.workflow.DisableUserStepProviderFactory;
import org.iamshield.models.workflow.WorkflowsManager;
import org.iamshield.models.workflow.SetUserAttributeStepProviderFactory;
import org.iamshield.models.workflow.UserCreationTimeWorkflowProviderFactory;
import org.iamshield.representations.idm.CredentialRepresentation;
import org.iamshield.representations.idm.ErrorRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.representations.workflows.WorkflowStepRepresentation;
import org.iamshield.representations.workflows.WorkflowRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;

@IAMShieldIntegrationTest(config = WorkflowsServerConfig.class)
public class AggregatedStepTest {

    private static final String REALM_NAME = "default";

    @InjectRunOnServer(permittedPackages = "org.iamshield.tests")
    RunOnServerClient runOnServer;

    @InjectRealm(lifecycle = LifeCycle.METHOD)
    ManagedRealm managedRealm;

    @Test
    public void testCreate() {
        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .withSteps(
                        WorkflowStepRepresentation.create().of(AggregatedStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .withSteps(WorkflowStepRepresentation.create()
                                                .of(SetUserAttributeStepProviderFactory.ID)
                                                .withConfig("message", "message")
                                                .build(),
                                        WorkflowStepRepresentation.create()
                                                .of(DisableUserStepProviderFactory.ID)
                                                .build()
                                ).build())
                .build()).close();

        List<WorkflowRepresentation> workflows = managedRealm.admin().workflows().list();
        assertThat(workflows, hasSize(1));
        WorkflowRepresentation workflow = workflows.get(0);
        assertThat(workflow.getSteps(), hasSize(1));
        WorkflowStepRepresentation aggregatedStep = workflow.getSteps().get(0);
        assertThat(aggregatedStep.getProviderId(), is(AggregatedStepProviderFactory.ID));
        List<WorkflowStepRepresentation> steps = aggregatedStep.getSteps();
        assertThat(steps, hasSize(2));
        assertStep(steps, SetUserAttributeStepProviderFactory.ID, a -> {
            assertNotNull(a.getConfig());
            assertThat(a.getConfig().isEmpty(), is(false));
            assertThat(a.getConfig(), hasEntry("priority", List.of("1")));
            assertThat(a.getConfig(), hasEntry("message", List.of("message")));
        });
        assertStep(steps, DisableUserStepProviderFactory.ID, a -> {
            assertNotNull(a.getConfig());
            assertThat(a.getConfig().isEmpty(), is(false));
            assertThat(a.getConfig(), hasEntry("priority", List.of("2")));
        });
    }

    @Test
    public void testCreateAggregatedStepAsSubStep() {
        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .withSteps(
                        WorkflowStepRepresentation.create().of(AggregatedStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .withSteps(WorkflowStepRepresentation.create()
                                                .of(AggregatedStepProviderFactory.ID)
                                                .withConfig("message", "message")
                                                .after(Duration.ofDays(5))
                                                .withSteps(WorkflowStepRepresentation.create()
                                                                .of(SetUserAttributeStepProviderFactory.ID)
                                                                .withConfig("message", "message")
                                                                .build(),
                                                        WorkflowStepRepresentation.create()
                                                                .of(DisableUserStepProviderFactory.ID)
                                                                .build()
                                                )
                                                .build(),
                                        WorkflowStepRepresentation.create()
                                                .of(DisableUserStepProviderFactory.ID)
                                                .build()
                                ).build())
                .build()).close();

        List<WorkflowRepresentation> workflows = managedRealm.admin().workflows().list();
        assertThat(workflows, hasSize(1));
    }

    @Test
    public void testFailCreateIfSettingStepsToRegularSteps() {
        try (Response response = managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .withSteps(
                        WorkflowStepRepresentation.create().of(SetUserAttributeStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .withConfig("key", "value")
                                .withSteps(WorkflowStepRepresentation.create()
                                                .of(SetUserAttributeStepProviderFactory.ID)
                                                .withConfig("message", "message")
                                                .build(),
                                        WorkflowStepRepresentation.create()
                                                .of(DisableUserStepProviderFactory.ID)
                                                .build()
                                ).build())
                .build())) {
            assertThat(response.getStatus(), is(Status.BAD_REQUEST.getStatusCode()));
            assertThat(response.readEntity(ErrorRepresentation.class).getErrorMessage(), equalTo("Step provider " + SetUserAttributeStepProviderFactory.ID + " does not support aggregated steps"));
        }
    }

    @Test
    public void testFailCreateIfSubStepHasTimeCondition() {
        try (Response response = managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .withSteps(
                        WorkflowStepRepresentation.create().of(SetUserAttributeStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .withConfig("key", "value")
                                .withSteps(WorkflowStepRepresentation.create()
                                                .of(SetUserAttributeStepProviderFactory.ID)
                                                .withConfig("message", "message")
                                                .after(Duration.ofDays(1))
                                                .build(),
                                        WorkflowStepRepresentation.create()
                                                .of(DisableUserStepProviderFactory.ID)
                                                .build()
                                ).build())
                .build())) {
            assertThat(response.getStatus(), is(Status.BAD_REQUEST.getStatusCode()));
            assertThat(response.readEntity(ErrorRepresentation.class).getErrorMessage(), equalTo("Step provider " + SetUserAttributeStepProviderFactory.ID + " does not support aggregated steps"));
        }
    }

    @Test
    public void testStepRun() {
        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .withSteps(
                        WorkflowStepRepresentation.create().of(AggregatedStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .withSteps(WorkflowStepRepresentation.create()
                                                .of(SetUserAttributeStepProviderFactory.ID)
                                                .withConfig("message", "message")
                                                .build(),
                                        WorkflowStepRepresentation.create()
                                                .of(DisableUserStepProviderFactory.ID)
                                                .build()
                                ).build())
                .build()).close();

        managedRealm.admin().users().create(getUserRepresentation("alice", "Alice", "Wonderland", "alice@wornderland.org")).close();

        runOnServer.run((session -> {
            RealmModel realm = configureSessionContext(session);
            WorkflowsManager manager = new WorkflowsManager(session);

            try {
                Time.setOffset(Math.toIntExact(Duration.ofDays(6).toSeconds()));
                manager.runScheduledSteps();
                UserModel user = session.users().getUserByUsername(realm, "alice");
                assertNotNull(user.getAttributes().get("message"));
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

    private void assertStep(List<WorkflowStepRepresentation> steps, String expectedProviderId, Consumer<WorkflowStepRepresentation> assertions) {
        assertTrue(steps.stream()
                .anyMatch(a -> {
                    if (a.getProviderId().equals(expectedProviderId)) {
                        assertions.accept(a);
                        return true;
                    }
                    return false;
                }));
    }
}
