package org.iamshield.models.workflow.conditions;

import static org.iamshield.common.util.CollectionUtil.collectionEquals;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.workflow.WorkflowConditionProvider;
import org.iamshield.models.workflow.WorkflowEvent;
import org.iamshield.models.workflow.ResourceType;

public class UserAttributeWorkflowConditionProvider implements WorkflowConditionProvider {

    private final Map<String, List<String>> expectedAttributes;
    private final IAMShieldSession session;

    public UserAttributeWorkflowConditionProvider(IAMShieldSession session, Map<String, List<String>> expectedAttributes) {
        this.session = session;
        this.expectedAttributes = expectedAttributes;;
    }

    @Override
    public boolean evaluate(WorkflowEvent event) {
        if (!ResourceType.USERS.equals(event.getResourceType())) {
            return false;
        }

        String userId = event.getResourceId();
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);

        if (user == null) {
            return false;
        }

        for (Entry<String, List<String>> expected : expectedAttributes.entrySet()) {
            List<String> values = user.getAttributes().getOrDefault(expected.getKey(), List.of());
            List<String> expectedValues = expected.getValue();

            if (!collectionEquals(expectedValues, values)) {
                return false;
            }
        }

        return true;
    }

    @Override
    public void validate() {
        // no-op
    }

    @Override
    public void close() {

    }
}
