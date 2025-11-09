package org.iamshield.models.workflow;

import java.util.List;
import java.util.Map;

import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.ProviderFactory;

public interface WorkflowConditionProviderFactory<P extends WorkflowConditionProvider> extends ProviderFactory<P>, EnvironmentDependentProviderFactory {

    P create(IAMShieldSession session, Map<String, List<String>> config);

    @Override
    default P create(IAMShieldSession session) {
        throw new IllegalStateException("Use create(IAMShieldSession session, MultivaluedHashMap<String, String> config) instead.");
    }

    @Override
    default boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.WORKFLOWS);
    }
}
