package org.iamshield.broker.spiffe;

import org.iamshield.crypto.PublicKeysWrapper;
import org.iamshield.jose.jwk.JSONWebKeySet;
import org.iamshield.jose.jwk.JWK;
import org.iamshield.keys.PublicKeyLoader;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.protocol.oidc.utils.JWKSHttpUtils;
import org.iamshield.util.JWKSUtils;

public class SpiffeBundleEndpointLoader implements PublicKeyLoader {

    private final IAMShieldSession session;
    private final String bundleEndpoint;

    public SpiffeBundleEndpointLoader(IAMShieldSession session, String bundleEndpoint) {
        this.session = session;
        this.bundleEndpoint = bundleEndpoint;
    }

    @Override
    public PublicKeysWrapper loadKeys() throws Exception {
        JSONWebKeySet jwks = JWKSHttpUtils.sendJwksRequest(session, bundleEndpoint);
        return JWKSUtils.getKeyWrappersForUse(jwks, JWK.Use.JWT_SVID);
    }

}
