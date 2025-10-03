package org.iamshield.models.workflow.conditions;

import java.util.List;

import org.iamshield.models.GroupModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.workflow.WorkflowConditionProvider;
import org.iamshield.models.workflow.WorkflowEvent;
import org.iamshield.models.workflow.WorkflowInvalidStateException;
import org.iamshield.models.workflow.ResourceType;

public class GroupMembershipWorkflowConditionProvider implements WorkflowConditionProvider {

    private final List<String> expectedGroups;
    private final IAMShieldSession session;

    public GroupMembershipWorkflowConditionProvider(IAMShieldSession session, List<String> expectedGroups) {
        this.session = session;
        this.expectedGroups = expectedGroups;;
    }

    @Override
    public boolean evaluate(WorkflowEvent event) {
        if (!ResourceType.USERS.equals(event.getResourceType())) {
            return false;
        }

        validate();

        String userId = event.getResourceId();
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);

        for (String expectedGroup : expectedGroups) {
            GroupModel group = session.groups().getGroupById(realm, expectedGroup);

            if (user.isMemberOf(group)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void validate() {
        expectedGroups.forEach(id -> {
            if (session.groups().getGroupById(session.getContext().getRealm(), id) == null) {
                throw new WorkflowInvalidStateException(String.format("Group with id %s does not exist.", id));
            }
        });
    }

    @Override
    public void close() {

    }
}
