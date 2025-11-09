package org.iamshield.models.workflow;

import java.util.List;

import org.iamshield.Config.Scope;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;

public class EventBasedWorkflowProviderFactory implements WorkflowProviderFactory {

    public static final String ID = "event-based-workflow";

    @Override
    public WorkflowProvider create(IAMShieldSession session, ComponentModel model) {
        return new EventBasedWorkflowProvider(session, model);
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public String getHelpText() {
        return "";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {

    }

}
