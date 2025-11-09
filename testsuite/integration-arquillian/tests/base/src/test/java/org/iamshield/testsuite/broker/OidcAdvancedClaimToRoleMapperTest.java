package org.iamshield.testsuite.broker;

import org.iamshield.broker.oidc.mappers.AdvancedClaimToRoleMapper;
import org.iamshield.broker.provider.ConfigConstants;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.representations.idm.IdentityProviderMapperRepresentation;

import java.util.HashMap;
import java.util.Map;

/**
 * <a href="mailto:external.benjamin.weimer@bosch-si.com">Benjamin Weimer</a>,
 * <a href="mailto:external.martin.idel@bosch.io">Martin Idel</a>,
 * <a href="mailto:daniel.fesenmeyer@bosch.io">Daniel Fesenmeyer</a>
 */
public class OidcAdvancedClaimToRoleMapperTest extends AbstractAdvancedRoleMapperTest {
    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration();
    }

    @Override
    protected void createMapperInIdp(String claimsOrAttributeRepresentation,
            boolean areClaimsOrAttributeValuesRegexes, IdentityProviderMapperSyncMode syncMode, String roleValue) {
        IdentityProviderMapperRepresentation advancedClaimToRoleMapper = new IdentityProviderMapperRepresentation();
        advancedClaimToRoleMapper.setName("advanced-claim-to-role-mapper");
        advancedClaimToRoleMapper.setIdentityProviderMapper(AdvancedClaimToRoleMapper.PROVIDER_ID);

        final Map<String, String> config = new HashMap<>();
        config.put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString());
        config.put(AdvancedClaimToRoleMapper.CLAIM_PROPERTY_NAME, claimsOrAttributeRepresentation);
        config.put(AdvancedClaimToRoleMapper.ARE_CLAIM_VALUES_REGEX_PROPERTY_NAME,
                Boolean.valueOf(areClaimsOrAttributeValuesRegexes).toString());
        config.put(ConfigConstants.ROLE, roleValue);
        advancedClaimToRoleMapper.setConfig(config);

        persistMapper(advancedClaimToRoleMapper);
    }
}
