package org.iamshield.testsuite.broker;

import static org.iamshield.models.IdentityProviderMapperSyncMode.FORCE;
import static org.iamshield.models.IdentityProviderMapperSyncMode.LEGACY;

import org.junit.Test;
import org.iamshield.broker.provider.ConfigConstants;
import org.iamshield.broker.saml.mappers.AttributeToRoleMapper;
import org.iamshield.broker.saml.mappers.UserAttributeMapper;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.representations.idm.IdentityProviderMapperRepresentation;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:external.martin.idel@bosch.io">Martin Idel</a>
 */
public class AttributeToRoleMapperTest extends AbstractRoleMapperTest {

    private static final String ROLE_ATTR_NAME = "Role";

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcSamlBrokerConfiguration();
    }

    @Test
    public void mapperGrantsRoleOnFirstLogin() {
        createMapperThenLoginAsUserTwiceWithAttributeToRoleMapper();

        assertThatRoleHasBeenAssignedInConsumerRealm();
    }

    @Test
    public void updateBrokeredUserGrantsRoleInLegacyMode() {
        loginAsUserThenCreateMapperAndLoginAgainWithAttributeToRoleMapper(LEGACY);

        assertThatRoleHasBeenAssignedInConsumerRealm();
    }

    @Test
    public void updateBrokeredUserGrantsRoleInForceMode() {
        loginAsUserThenCreateMapperAndLoginAgainWithAttributeToRoleMapper(FORCE);

        assertThatRoleHasBeenAssignedInConsumerRealm();
    }

    private void createMapperThenLoginAsUserTwiceWithAttributeToRoleMapper() {
        loginAsUserTwiceWithMapper(IdentityProviderMapperSyncMode.FORCE, false,
                createUserConfigForRole(CLIENT_ROLE_MAPPER_REPRESENTATION));
    }

    private void loginAsUserThenCreateMapperAndLoginAgainWithAttributeToRoleMapper(
            IdentityProviderMapperSyncMode syncMode) {
        loginAsUserTwiceWithMapper(syncMode, true, createUserConfigForRole(CLIENT_ROLE_MAPPER_REPRESENTATION));
    }

    @Override
    protected void createMapperInIdp(IdentityProviderMapperSyncMode syncMode, String roleValue) {
        IdentityProviderMapperRepresentation samlAttributeToRoleMapper = new IdentityProviderMapperRepresentation();
        samlAttributeToRoleMapper.setName("user-role-mapper");
        samlAttributeToRoleMapper.setIdentityProviderMapper(AttributeToRoleMapper.PROVIDER_ID);
        samlAttributeToRoleMapper.setConfig(ImmutableMap.<String, String> builder()
                .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
                .put(UserAttributeMapper.ATTRIBUTE_NAME, ROLE_ATTR_NAME)
                .put(ATTRIBUTE_VALUE, ROLE_USER)
                .put(ConfigConstants.ROLE, roleValue)
                .build());

        persistMapper(samlAttributeToRoleMapper);
    }

    protected Map<String, List<String>> createUserConfigForRole(String roleValue) {
        return ImmutableMap.<String, List<String>> builder()
                .put(ROLE_ATTR_NAME, ImmutableList.<String> builder().add(roleValue).build())
                .build();
    }
}
