package org.iamshield.protocol.docker;

import org.iamshield.Config;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.AuthenticatorFactory;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

import static org.iamshield.models.AuthenticationExecutionModel.Requirement;

public class DockerAuthenticatorFactory implements AuthenticatorFactory {

    @Override
    public String getHelpText() {
        return "Uses HTTP Basic authentication to validate docker users, returning a docker error token on auth failure";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public String getDisplayType() {
        return "Docker Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "docker";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
    };

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }


    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public Authenticator create(IAMShieldSession session) {
        return new DockerAuthenticator();
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
        return DockerAuthenticator.ID;
    }

}
