package org.iamshield.testsuite.broker;

import org.iamshield.admin.client.resource.IdentityProviderResource;
import org.iamshield.broker.oidc.mappers.UsernameTemplateMapper;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.representations.idm.IdentityProviderMapperRepresentation;
import org.iamshield.representations.idm.IdentityProviderRepresentation;

import com.google.common.collect.ImmutableMap;

/**
 * @author <a href="mailto:external.martin.idel@bosch.io">Martin Idel</a>
 */
public class KcOidcUsernameTemplateMapperTest extends AbstractUsernameTemplateMapperTest {
    @Override
    protected void createMapperInIdp(IdentityProviderRepresentation idp, IdentityProviderMapperSyncMode syncMode) {
        IdentityProviderMapperRepresentation usernameTemplateMapper = new IdentityProviderMapperRepresentation();
        usernameTemplateMapper.setName("oidc-username-template-mapper");
        usernameTemplateMapper.setIdentityProviderMapper(UsernameTemplateMapper.PROVIDER_ID);
        usernameTemplateMapper.setConfig(ImmutableMap.<String, String>builder()
                .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
                .put("template", "${ALIAS}-${CLAIM.user-attribute}")
                .build());

        IdentityProviderResource idpResource = realm.identityProviders().get(idp.getAlias());
        usernameTemplateMapper.setIdentityProviderAlias(bc.getIDPAlias());
        idpResource.addMapper(usernameTemplateMapper).close();
    }

    @Override
    protected String getMapperTemplate() {
        return "kc-oidc-idp-%s";
    }

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration();
    }
}
