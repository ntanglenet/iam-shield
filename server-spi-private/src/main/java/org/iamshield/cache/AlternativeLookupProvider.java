package org.iamshield.cache;

import org.iamshield.models.ClientModel;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.Provider;

import java.util.Map;

public interface AlternativeLookupProvider extends Provider {

    IdentityProviderModel lookupIdentityProviderFromIssuer(IAMShieldSession session, String issuerUrl);

    ClientModel lookupClientFromClientAttributes(IAMShieldSession session, Map<String, String> attributes);

}
