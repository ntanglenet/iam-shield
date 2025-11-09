package org.iamshield.models.workflow.conditions;

import java.util.List;
import java.util.Map;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.workflow.WorkflowConditionProviderFactory;

public class IdentityProviderWorkflowConditionFactory implements WorkflowConditionProviderFactory<IdentityProviderWorkflowConditionProvider> {

    public static final String ID = "identity-provider-condition";
    public static final String EXPECTED_ALIASES = "alias";

    @Override
    public IdentityProviderWorkflowConditionProvider create(IAMShieldSession session, Map<String, List<String>> config) {
        return new IdentityProviderWorkflowConditionProvider(session, config.get(EXPECTED_ALIASES));
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
