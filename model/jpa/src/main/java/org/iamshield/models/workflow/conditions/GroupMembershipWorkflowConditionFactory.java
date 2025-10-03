package org.iamshield.models.workflow.conditions;

import java.util.List;
import java.util.Map;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.workflow.WorkflowConditionProviderFactory;

public class GroupMembershipWorkflowConditionFactory implements WorkflowConditionProviderFactory<GroupMembershipWorkflowConditionProvider> {

    public static final String ID = "group-membership-condition";
    public static final String EXPECTED_GROUPS = "groups";

    @Override
    public GroupMembershipWorkflowConditionProvider create(IAMShieldSession session, Map<String, List<String>> config) {
        return new GroupMembershipWorkflowConditionProvider(session, config.get(EXPECTED_GROUPS));
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void init(org.iamshield.Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
    }

}
