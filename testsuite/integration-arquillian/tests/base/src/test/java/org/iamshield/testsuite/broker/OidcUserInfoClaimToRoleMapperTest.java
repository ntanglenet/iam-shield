package org.iamshield.testsuite.broker;

import org.junit.Test;
import org.iamshield.broker.oidc.mappers.ClaimToRoleMapper;
import org.iamshield.broker.provider.ConfigConstants;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.protocol.ProtocolMapperUtils;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.iamshield.protocol.oidc.mappers.UserAttributeMapper;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.IdentityProviderMapperRepresentation;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;
import org.iamshield.representations.idm.UserRepresentation;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:dashaylan@gmail.com">Dashaylan Naidoo</a>,
 * <a href="mailto:daniel.fesenmeyer@bosch.io">Daniel Fesenmeyer</a>
 */
public class OidcUserInfoClaimToRoleMapperTest extends AbstractRoleMapperTest {

    protected static final String ATTRIBUTE_TO_MAP_USER_INFO = "user-attribute-info";
    private static final String USER_INFO_CLAIM = ATTRIBUTE_TO_MAP_USER_INFO;
    private static final String USER_INFO_CLAIM_VALUE = "value 1";
    private static final String CLAIM_ON_SECOND_LOGIN = "";


    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfigurationUserInfoOnlyMappers();
    }

    @Test
    public void singleClaimValueInUserInfoMatches() {
        createClaimToRoleMapper();
        createUserInProviderRealm(createUserConfig());

        logInAsUserInIDPForFirstTime();

        assertThatRoleHasBeenAssignedInConsumerRealm();
    }

    @Test
    public void noRoleAddedIfUserInfoDisabledAndOnlyClaimIsInUserInfo() {
        createClaimToRoleMapperWithUserInfoDisabledInIdP();
        createUserInProviderRealm(createUserConfig());

        logInAsUserInIDPForFirstTime();

        assertThatRoleHasNotBeenAssignedInConsumerRealm();
    }

    private void createClaimToRoleMapper() {
        setupIdentityProvider();
        createClaimToRoleMapper(OidcUserInfoClaimToRoleMapperTest.USER_INFO_CLAIM_VALUE,
                IdentityProviderMapperSyncMode.IMPORT, CLIENT_ROLE_MAPPER_REPRESENTATION);
    }

    private void createClaimToRoleMapperWithUserInfoDisabledInIdP() {
        setupIdentityProviderDisableUserInfo();
        createClaimToRoleMapper(OidcUserInfoClaimToRoleMapperTest.USER_INFO_CLAIM_VALUE,
                IdentityProviderMapperSyncMode.IMPORT, CLIENT_ROLE_MAPPER_REPRESENTATION);
    }

    @Override
    protected void createMapperInIdp(IdentityProviderMapperSyncMode syncMode, String roleValue) {
        createClaimToRoleMapper(USER_INFO_CLAIM_VALUE, syncMode, roleValue);
    }

    @Override
    protected void updateUser() {
        UserRepresentation user = findUser(bc.providerRealmName(), bc.getUserLogin(), bc.getUserEmail());
        ImmutableMap<String, List<String>> mismatchingAttributes = ImmutableMap.<String, List<String>> builder()
                .put(USER_INFO_CLAIM, ImmutableList.<String> builder().add(CLAIM_ON_SECOND_LOGIN).build())
                .build();
        user.setAttributes(mismatchingAttributes);
        adminClient.realm(bc.providerRealmName()).users().get(user.getId()).update(user);
    }

    private void createClaimToRoleMapper(String claimValue, IdentityProviderMapperSyncMode syncMode, String roleValue) {
        IdentityProviderMapperRepresentation claimToRoleMapper = new IdentityProviderMapperRepresentation();
        claimToRoleMapper.setName("userinfo-claim-to-role-mapper");
        claimToRoleMapper.setIdentityProviderMapper(ClaimToRoleMapper.PROVIDER_ID);
        claimToRoleMapper.setConfig(ImmutableMap.<String, String> builder()
                .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
                .put(ClaimToRoleMapper.CLAIM, OidcUserInfoClaimToRoleMapperTest.USER_INFO_CLAIM)
                .put(ClaimToRoleMapper.CLAIM_VALUE, claimValue)
                .put(ConfigConstants.ROLE, roleValue)
                .build());

        persistMapper(claimToRoleMapper);
    }

    private class KcOidcBrokerConfigurationUserInfoOnlyMappers extends KcOidcBrokerConfiguration {

        @Override
        public List<ClientRepresentation> createProviderClients() {
            List<ClientRepresentation> clientsRepList = super.createProviderClients();
            log.info("Update provider clients to disable attributes in Access & ID token");

            ProtocolMapperRepresentation userAttrMapper = new ProtocolMapperRepresentation();
            userAttrMapper.setName("attribute - name");
            userAttrMapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            userAttrMapper.setProtocolMapper(UserAttributeMapper.PROVIDER_ID);

            Map<String, String> userAttrMapperConfig = userAttrMapper.getConfig();
            userAttrMapperConfig.put(ProtocolMapperUtils.USER_ATTRIBUTE, ATTRIBUTE_TO_MAP_USER_INFO);
            userAttrMapperConfig.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, ATTRIBUTE_TO_MAP_USER_INFO);
            userAttrMapperConfig.put(OIDCAttributeMapperHelper.JSON_TYPE, ProviderConfigProperty.STRING_TYPE);
            userAttrMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "false");
            userAttrMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "false");
            userAttrMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");

            for (ClientRepresentation client : clientsRepList) {
                client.setProtocolMappers(Collections.singletonList(userAttrMapper));
            }

            return clientsRepList;

        }

        @Override
        protected void applyDefaultConfiguration(final Map<String, String> config, IdentityProviderSyncMode syncMode) {
            super.applyDefaultConfiguration(config, syncMode);
            config.put("disableUserInfo", "false");
        }
    }

    @Override
    protected Map<String, List<String>> createUserConfigForRole(String roleValue) {
        return createUserConfig();
    }

    private static Map<String, List<String>> createUserConfig() {
        return ImmutableMap.<String, List<String>> builder()
                .put(USER_INFO_CLAIM, ImmutableList.<String> builder().add(USER_INFO_CLAIM_VALUE).build())
                .build();
    }
}
