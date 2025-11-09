package org.iamshield.testsuite.broker;

import org.iamshield.broker.oidc.mappers.UserAttributeMapper;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.representations.idm.IdentityProviderMapperRepresentation;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;

public class OidcUserAttributeMapperTest extends AbstractUserAttributeMapperTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcOidcBrokerConfiguration.INSTANCE;
    }

    @Override
    protected Iterable<IdentityProviderMapperRepresentation> createIdentityProviderMappers(IdentityProviderMapperSyncMode syncMode) {
        IdentityProviderMapperRepresentation attrMapper1 = new IdentityProviderMapperRepresentation();
        attrMapper1.setName("attribute-mapper");
        attrMapper1.setIdentityProviderMapper(UserAttributeMapper.PROVIDER_ID);
        attrMapper1.setConfig(ImmutableMap.<String,String>builder()
          .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
          .put(UserAttributeMapper.CLAIM, KcOidcBrokerConfiguration.ATTRIBUTE_TO_MAP_NAME)
          .put(UserAttributeMapper.USER_ATTRIBUTE, MAPPED_ATTRIBUTE_NAME)
          .build());

        IdentityProviderMapperRepresentation emailAttrMapper = new IdentityProviderMapperRepresentation();
        emailAttrMapper.setName("attribute-mapper-email");
        emailAttrMapper.setIdentityProviderMapper(UserAttributeMapper.PROVIDER_ID);
        emailAttrMapper.setConfig(ImmutableMap.<String,String>builder()
          .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
          .put(UserAttributeMapper.CLAIM, "email")
          .put(UserAttributeMapper.USER_ATTRIBUTE, "email")
          .build());

        IdentityProviderMapperRepresentation nestedEmailAttrMapper = new IdentityProviderMapperRepresentation();
        nestedEmailAttrMapper.setName("nested-attribute-mapper-email");
        nestedEmailAttrMapper.setIdentityProviderMapper(UserAttributeMapper.PROVIDER_ID);
        nestedEmailAttrMapper.setConfig(ImmutableMap.<String,String>builder()
          .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
          .put(UserAttributeMapper.CLAIM, "nested.email")
          .put(UserAttributeMapper.USER_ATTRIBUTE, "nested.email")
          .build());

        IdentityProviderMapperRepresentation dottedEmailAttrMapper = new IdentityProviderMapperRepresentation();
        dottedEmailAttrMapper.setName("dotted-attribute-mapper-email");
        dottedEmailAttrMapper.setIdentityProviderMapper(UserAttributeMapper.PROVIDER_ID);
        dottedEmailAttrMapper.setConfig(ImmutableMap.<String,String>builder()
          .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
          .put(UserAttributeMapper.CLAIM, "dotted\\.email")
          .put(UserAttributeMapper.USER_ATTRIBUTE, "dotted.email")
          .build());

        return Lists.newArrayList(attrMapper1, emailAttrMapper, nestedEmailAttrMapper, dottedEmailAttrMapper);
    }

}
