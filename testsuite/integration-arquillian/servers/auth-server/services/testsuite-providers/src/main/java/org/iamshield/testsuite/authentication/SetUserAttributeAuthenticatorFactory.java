package org.iamshield.testsuite.authentication;

import org.iamshield.Config;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.AuthenticatorFactory;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;


public class SetUserAttributeAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "set-attribute";

    public static final String CONF_ATTR_NAME = "attr_name";
    public static final String CONF_ATTR_VALUE = "attr_value";
    protected static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }


    @Override
    public String getHelpText() {
        return "Set a user attribute";
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(IAMShieldSession keycloakSession) {
        return new SetUserAttributeAuthenticator();
    }

    @Override
    public String getDisplayType() {
        return "Set user attribute";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty attributeName = new ProviderConfigProperty();
        attributeName.setType(ProviderConfigProperty.STRING_TYPE);
        attributeName.setName(CONF_ATTR_NAME);
        attributeName.setLabel("Attribute name");
        attributeName.setHelpText("Name of the user attribute to set");

        ProviderConfigProperty attributeValue = new ProviderConfigProperty();
        attributeValue.setType(ProviderConfigProperty.STRING_TYPE);
        attributeValue.setName(CONF_ATTR_VALUE);
        attributeValue.setLabel("Attribute value");
        attributeValue.setHelpText("Value to set in the user attribute");

        return Arrays.asList(attributeName, attributeValue);
    }
}
