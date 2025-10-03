package org.iamshield.broker.spiffe;

import org.iamshield.Config;
import org.iamshield.broker.provider.AbstractIdentityProviderFactory;
import org.iamshield.common.Profile;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.EnvironmentDependentProviderFactory;

import java.util.Map;

public class SpiffeIdentityProviderFactory extends AbstractIdentityProviderFactory<SpiffeIdentityProvider> implements EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "spiffe";

    @Override
    public String getName() {
        return "SPIFFE";
    }

    @Override
    public SpiffeIdentityProvider create(IAMShieldSession session, IdentityProviderModel model) {
        return new SpiffeIdentityProvider(session, new SpiffeIdentityProviderConfig(model));
    }

    @Override
    public Map<String, String> parseConfig(IAMShieldSession session, String configString) {
        throw new UnsupportedOperationException();
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new SpiffeIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.SPIFFE);
    }

}
