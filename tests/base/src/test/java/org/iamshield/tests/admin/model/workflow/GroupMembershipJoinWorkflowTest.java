package org.iamshield.tests.admin.model.workflow;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Duration;
import java.util.List;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.admin.client.resource.WorkflowsResource;
import org.iamshield.common.util.Time;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.workflow.EventBasedWorkflowProviderFactory;
import org.iamshield.models.workflow.NotifyUserStepProviderFactory;
import org.iamshield.models.workflow.UserSessionRefreshTimeWorkflowProviderFactory;
import org.iamshield.models.workflow.SetUserAttributeStepProviderFactory;
import org.iamshield.models.workflow.conditions.GroupMembershipWorkflowConditionFactory;
import org.iamshield.models.workflow.ResourceOperationType;
import org.iamshield.models.workflow.WorkflowsManager;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.representations.workflows.WorkflowStepRepresentation;
import org.iamshield.representations.workflows.WorkflowConditionRepresentation;
import org.iamshield.representations.workflows.WorkflowRepresentation;
import org.iamshield.representations.userprofile.config.UPConfig;
import org.iamshield.representations.userprofile.config.UPConfig.UnmanagedAttributePolicy;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.realm.GroupConfigBuilder;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.util.ApiUtil;

@IAMShieldIntegrationTest(config = WorkflowsServerConfig.class)
public class GroupMembershipJoinWorkflowTest {

    private static final String REALM_NAME = "default";

    @InjectRunOnServer(permittedPackages = "org.iamshield.tests")
    RunOnServerClient runOnServer;

    @InjectRealm(lifecycle = LifeCycle.METHOD)
    ManagedRealm managedRealm;

    @Test
    public void testEventsOnGroupMembershipJoin() {
        UPConfig upConfig = managedRealm.admin().users().userProfile().getConfiguration();
        upConfig.setUnmanagedAttributePolicy(UnmanagedAttributePolicy.ENABLED);
        managedRealm.admin().users().userProfile().update(upConfig);
        String groupId;

        try (Response response = managedRealm.admin().groups().add(GroupConfigBuilder.create()
                .name("generic-group").build())) {
            groupId = ApiUtil.getCreatedId(response);
        }

        List<WorkflowRepresentation> expectedWorkflows = WorkflowRepresentation.create()
                .of(EventBasedWorkflowProviderFactory.ID)
                .onEvent(ResourceOperationType.USER_GROUP_MEMBERSHIP_ADD.name())
                .onConditions(WorkflowConditionRepresentation.create()
                        .of(GroupMembershipWorkflowConditionFactory.ID)
                        .withConfig(GroupMembershipWorkflowConditionFactory.EXPECTED_GROUPS, groupId)
                        .build())
                .withSteps(
                        WorkflowStepRepresentation.create()
                                .of(SetUserAttributeStepProviderFactory.ID)
                                .withConfig("attribute", "attr1")
                                .after(Duration.ofDays(5))
                                .build()
                ).build();

        WorkflowsResource workflows = managedRealm.admin().workflows();

        try (Response response = workflows.create(expectedWorkflows)) {
            assertThat(response.getStatus(), is(Status.CREATED.getStatusCode()));
        }

        String userId;

        try (Response response = managedRealm.admin().users().create(UserConfigBuilder.create()
                .username("generic-user").email("generic-user@example.com").build())) {
            userId = ApiUtil.getCreatedId(response);
        }

        UserResource userResource = managedRealm.admin().users().get(userId);

        userResource.joinGroup(groupId);

        runOnServer.run((session -> {
            RealmModel realm = configureSessionContext(session);
            WorkflowsManager manager = new WorkflowsManager(session);

            try {
                // set offset to 7 days - notify step should run now
                Time.setOffset(Math.toIntExact(Duration.ofDays(6).toSeconds()));
                manager.runScheduledSteps();
            } finally {
                Time.setOffset(0);
            }
        }));

        UserRepresentation rep = userResource.toRepresentation();
        assertNotNull(rep.getAttributes().get("attribute"));
    }

    @Test
    public void testRemoveAssociatedGroup() {
        String groupId;

        try (Response response = managedRealm.admin().groups().add(GroupConfigBuilder.create()
                .name("generic-group").build())) {
            groupId = ApiUtil.getCreatedId(response);
        }

        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserSessionRefreshTimeWorkflowProviderFactory.ID)
                .onEvent(ResourceOperationType.USER_LOGIN.toString())
                .onConditions(WorkflowConditionRepresentation.create()
                        .of(GroupMembershipWorkflowConditionFactory.ID)
                        .withConfig(GroupMembershipWorkflowConditionFactory.EXPECTED_GROUPS, groupId)
                        .build())
                .withSteps(
                        WorkflowStepRepresentation.create().of(NotifyUserStepProviderFactory.ID)
                                .after(Duration.ofDays(1))
                                .build()
                ).build()).close();

        List<WorkflowRepresentation> workflows = managedRealm.admin().workflows().list();
        assertThat(workflows, hasSize(1));

        WorkflowRepresentation workflowRep = managedRealm.admin().workflows().workflow(workflows.get(0).getId()).toRepresentation();
        assertThat(workflowRep.getConfig().getFirst("enabled"), nullValue());

        // remove group
        managedRealm.admin().groups().group(groupId).remove();

        // create new user - it will trigger an activation event and therefore should disable the workflow
        managedRealm.admin().users().create(UserConfigBuilder.create().username("test").build()).close();

        // check the workflow is disabled
        workflowRep = managedRealm.admin().workflows().workflow(workflows.get(0).getId()).toRepresentation();
        assertThat(workflowRep.getConfig().getFirst("enabled"), allOf(notNullValue(), is("false")));
        List<String> validationErrors = workflowRep.getConfig().get("validation_error");
        assertThat(validationErrors, notNullValue());
        assertThat(validationErrors, hasSize(1));
        assertThat(validationErrors.get(0), containsString("Group with id %s does not exist.".formatted(groupId)));
    }

    private static RealmModel configureSessionContext(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName(REALM_NAME);
        session.getContext().setRealm(realm);
        return realm;
    }
}
