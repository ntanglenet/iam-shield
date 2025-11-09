package org.iamshield.testsuite.broker;

import org.iamshield.admin.client.CreatedResponseUtil;
import org.iamshield.admin.client.resource.IdentityProviderResource;
import org.iamshield.broker.provider.ConfigConstants;
import org.iamshield.broker.provider.HardcodedGroupMapper;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.representations.idm.IdentityProviderMapperRepresentation;
import org.iamshield.representations.idm.IdentityProviderRepresentation;

import com.google.common.collect.ImmutableMap;

import jakarta.ws.rs.core.Response;

/**
 * @author <a href="mailto:dmartino@redhat.com">DanieleMartinoli</a>
 * 
 * For simplicity, it overrides OidcAdvancedClaimToGroupMapperTest with an Hardcoded Group mapper to run
 * all tests from the super class.
 * 
 * Since this mapper does not cause leaving the group when the claims do not match, an <code>isHardcodedGroup</code>
 * method is introduced to customize the behavior in the super class.
 */
public class OidcHardcodedGroupMapperTest extends OidcAdvancedClaimToGroupMapperTest {
    @Override
    protected boolean isHardcodedGroup() {
        return true;
    }

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration();
    }

    @Override
    protected String createMapperInIdp(IdentityProviderRepresentation idp, String claimsOrAttributeRepresentation,
            boolean areClaimsOrAttributeValuesRegexes, IdentityProviderMapperSyncMode syncMode, String groupPath) {
        IdentityProviderMapperRepresentation hardcodedGroupMapper = new IdentityProviderMapperRepresentation();
        hardcodedGroupMapper.setName("hardcoded-group-mapper");
        hardcodedGroupMapper.setIdentityProviderMapper(HardcodedGroupMapper.PROVIDER_ID);
        hardcodedGroupMapper.setConfig(ImmutableMap.<String, String> builder()
                .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
                .put(ConfigConstants.GROUP, groupPath)
                .build());

        IdentityProviderResource idpResource = realm.identityProviders().get(idp.getAlias());
        hardcodedGroupMapper.setIdentityProviderAlias(bc.getIDPAlias());
        Response response = idpResource.addMapper(hardcodedGroupMapper);
        return CreatedResponseUtil.getCreatedId(response);
    }
}
