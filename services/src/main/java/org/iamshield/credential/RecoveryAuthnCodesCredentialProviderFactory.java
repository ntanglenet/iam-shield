package org.iamshield.credential;

import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.EnvironmentDependentProviderFactory;

public class RecoveryAuthnCodesCredentialProviderFactory
        implements CredentialProviderFactory<RecoveryAuthnCodesCredentialProvider>, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "keycloak-recovery-authn-codes";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RecoveryAuthnCodesCredentialProvider create(IAMShieldSession session) {
        return new RecoveryAuthnCodesCredentialProvider(session);
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.RECOVERY_CODES);
    }
}
