package org.iamshield.models.workflow.conditions;

import java.util.List;
import java.util.Map;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.workflow.WorkflowConditionProviderFactory;

public class UserAttributeWorkflowConditionFactory implements WorkflowConditionProviderFactory<UserAttributeWorkflowConditionProvider> {

    public static final String ID = "user-attribute-condition";

    @Override
    public UserAttributeWorkflowConditionProvider create(IAMShieldSession session, Map<String, List<String>> config) {
        return new UserAttributeWorkflowConditionProvider(session, config);
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
