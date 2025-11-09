package org.iamshield.testsuite.broker.oidc;

import org.iamshield.broker.oidc.IAMShieldOIDCIdentityProvider;
import org.iamshield.broker.oidc.IAMShieldOIDCIdentityProviderFactory;
import org.iamshield.broker.oidc.OIDCIdentityProviderConfig;
import org.iamshield.broker.provider.IdentityProviderMapper;
import org.iamshield.models.IAMShieldSession;

import java.util.Arrays;
import java.util.List;

/**
 * @author Daniel Fesenmeyer <daniel.fesenmeyer@bosch.com>
 */
public class OverwrittenMappersTestIdentityProvider extends IAMShieldOIDCIdentityProvider {

    public OverwrittenMappersTestIdentityProvider(IAMShieldSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public boolean isMapperSupported(IdentityProviderMapper mapper) {
        List<String> compatibleIdps = Arrays.asList(mapper.getCompatibleProviders());

        // provide the same mappers as are available for the parent provider (IAMShield-OIDC)
        return compatibleIdps.contains(IdentityProviderMapper.ANY_PROVIDER)
                || compatibleIdps.contains(IAMShieldOIDCIdentityProviderFactory.PROVIDER_ID);
    }

}
