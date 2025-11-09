package org.iamshield.models.workflow;

import java.util.List;

import org.iamshield.Config;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ConfiguredProvider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;

public class AddRequiredActionStepProviderFactory implements WorkflowStepProviderFactory<AddRequiredActionStepProvider>, ConfiguredProvider {

    public static final String ID = "set-user-required-action";

    @Override
    public AddRequiredActionStepProvider create(IAMShieldSession session, ComponentModel model) {
        return new AddRequiredActionStepProvider(session, model);
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
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("action")
                .label("Required Action")
                .helpText("The required action to add to the user (e.g., UPDATE_PASSWORD)")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .build();
    }

    @Override
    public ResourceType getType() {
        return ResourceType.USERS;
    }

    @Override
    public String getHelpText() {
        return "";
    }
}
