package org.iamshield.models.workflow;

import java.util.List;

import org.iamshield.Config;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;

public class AggregatedStepProviderFactory implements WorkflowStepProviderFactory<AggregatedStepProvider> {

    public static final String ID = "aggregated-step-provider";

    @Override
    public AggregatedStepProvider create(IAMShieldSession session, ComponentModel model) {
        return new AggregatedStepProvider(session, model);
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public ResourceType getType() {
        return ResourceType.USERS;
    }

    @Override
    public String getHelpText() {
        return "";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
