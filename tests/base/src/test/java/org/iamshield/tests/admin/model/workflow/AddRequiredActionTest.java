package org.iamshield.tests.admin.model.workflow;

import org.junit.jupiter.api.Test;
import org.iamshield.models.UserModel;
import org.iamshield.models.workflow.AddRequiredActionStepProvider;
import org.iamshield.models.workflow.AddRequiredActionStepProviderFactory;
import org.iamshield.models.workflow.UserCreationTimeWorkflowProviderFactory;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.representations.workflows.WorkflowStepRepresentation;
import org.iamshield.representations.workflows.WorkflowRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.UserConfigBuilder;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@IAMShieldIntegrationTest(config = WorkflowsServerConfig.class)
public class AddRequiredActionTest {

    private static final String REALM_NAME = "default";

    @InjectRealm(lifecycle = LifeCycle.METHOD)
    ManagedRealm managedRealm;

    @Test
    public void testStepRun() {
        managedRealm.admin().workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .immediate()
                .withSteps(
                        WorkflowStepRepresentation.create()
                                .of(AddRequiredActionStepProviderFactory.ID)
                                .withConfig(AddRequiredActionStepProvider.REQUIRED_ACTION_KEY, "UPDATE_PASSWORD")
                                .build()
                ).build()).close();

        managedRealm.admin().users().create(UserConfigBuilder.create().username("test").build()).close();

        List< UserRepresentation> users = managedRealm.admin().users().search("test");
        assertThat(users, hasSize(1));
        UserRepresentation userRepresentation = users.get(0);
        assertThat(userRepresentation.getRequiredActions(), hasSize(1));
        assertThat(userRepresentation.getRequiredActions().get(0), is(UserModel.RequiredAction.UPDATE_PASSWORD.name()));
    }

}
