package org.iamshield.authentication.authenticators.browser;

import org.iamshield.Config;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.AuthenticatorFactory;
import org.iamshield.authentication.ConfigurableAuthenticatorFactory;
import org.iamshield.common.Profile;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.credential.RecoveryAuthnCodesCredentialModel;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.ProviderConfigProperty;

import java.util.List;

public class RecoveryAuthnCodesFormAuthenticatorFactory implements AuthenticatorFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "auth-recovery-authn-code-form";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Recovery Authentication Code Form";
    }

    @Override
    public String getReferenceCategory() {
        return RecoveryAuthnCodesCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Validates a Recovery Authentication Code";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public Authenticator create(IAMShieldSession keycloakSession) {
        return new RecoveryAuthnCodesFormAuthenticator(keycloakSession);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.RECOVERY_CODES);
    }
}
