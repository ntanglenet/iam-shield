package org.iamshield.models.workflow.conditions;

import java.util.List;
import java.util.Map;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.workflow.WorkflowConditionProviderFactory;

public class RoleWorkflowConditionFactory implements WorkflowConditionProviderFactory<RoleWorkflowConditionProvider> {

    public static final String ID = "role-condition";
    public static final String EXPECTED_ROLES = "roles";

    @Override
    public RoleWorkflowConditionProvider create(IAMShieldSession session, Map<String, List<String>> config) {
        return new RoleWorkflowConditionProvider(session, config.get(EXPECTED_ROLES));
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
