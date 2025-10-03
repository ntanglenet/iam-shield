package org.iamshield.protocol.saml.mappers;

import org.iamshield.models.AuthenticatedClientSessionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.protocol.ProtocolMapperUtils;
import org.iamshield.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class UserAttributeNameIdMapper extends AbstractSAMLProtocolMapper implements SAMLNameIdMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        NameIdMapperHelper.setConfigProperties(configProperties);
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.USER_ATTRIBUTE);
        property.setLabel(ProtocolMapperUtils.USER_MODEL_ATTRIBUTE_LABEL);
        property.setHelpText(ProtocolMapperUtils.USER_MODEL_ATTRIBUTE_HELP_TEXT);
        property.setType(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE);
        property.setRequired(Boolean.TRUE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-user-attribute-nameid-mapper";

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "User Attribute Mapper For NameID";
    }

    @Override
    public String getDisplayCategory() {
        return "NameID Mapper";
    }

    @Override
    public String getHelpText() {
        return "Map user attribute to SAML NameID value.";
    }

    @Override
    public String mapperNameId(String nameIdFormat, ProtocolMapperModel mappingModel, IAMShieldSession session,
            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        return userSession.getUser().getFirstAttribute(mappingModel.getConfig().get(ProtocolMapperUtils.USER_ATTRIBUTE));
    }

}
