package org.iamshield.broker.spiffe;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import org.iamshield.authentication.ClientAuthenticationFlowContext;
import org.iamshield.authentication.authenticators.client.AbstractJWTClientValidator;
import org.iamshield.authentication.authenticators.client.FederatedJWTClientValidator;
import org.iamshield.broker.provider.AuthenticationRequest;
import org.iamshield.broker.provider.BrokeredIdentityContext;
import org.iamshield.broker.provider.ClientAssertionIdentityProvider;
import org.iamshield.broker.provider.IdentityProvider;
import org.iamshield.broker.provider.IdentityProviderDataMarshaller;
import org.iamshield.crypto.KeyWrapper;
import org.iamshield.crypto.SignatureProvider;
import org.iamshield.events.EventBuilder;
import org.iamshield.jose.jws.JWSHeader;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.keys.PublicKeyStorageProvider;
import org.iamshield.keys.PublicKeyStorageUtils;
import org.iamshield.models.FederatedIdentityModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.representations.JsonWebToken;
import org.iamshield.sessions.AuthenticationSessionModel;

import java.nio.charset.StandardCharsets;

/**
 * Implementation for https://datatracker.ietf.org/doc/draft-schwenkschuster-oauth-spiffe-client-auth/
 *
 * Main differences for SPIFFE JWT SVIDs and regular client assertions:
 * <ul>
*  <li><code>jwt-spiffe</code> client assertion type</li>
 * <li><code>iss</code> claim is optional, uses SPIFFE IDs, which includes trust domain instead</li>
 * <li><code>jti</code> claim is optional, and SPIFFE vendors re-use/cache tokens</li>
 * <li><code>sub</code> is a SPIFFE ID with the syntax <code>spiffe://trust-domain/workload-identity</code></li>
 * <li>Keys are fetched from a SPIFFE bundle endpoint, where the JWKS has additional SPIFFE specific fields (<code>spiffe_sequence</code> and <code>spiffe_refresh_hint</code>, the JWK does not set the <code>alg></code></li>
 * </ul>
 */
public class SpiffeIdentityProvider implements IdentityProvider<SpiffeIdentityProviderConfig>, ClientAssertionIdentityProvider {

    private static final Logger LOGGER = Logger.getLogger(SpiffeIdentityProvider.class);

    private final IAMShieldSession session;
    private final SpiffeIdentityProviderConfig config;

    public SpiffeIdentityProvider(IAMShieldSession session, SpiffeIdentityProviderConfig config) {
        this.session = session;
        this.config = config;
    }

    @Override
    public SpiffeIdentityProviderConfig getConfig() {
        return config;
    }

    @Override
    public boolean verifyClientAssertion(ClientAuthenticationFlowContext context) throws Exception {
        FederatedJWTClientValidator validator = new FederatedJWTClientValidator(context, this::verifySignature,
                    null, config.getAllowedClockSkew(), true);
        validator.setExpectedClientAssertionType(SpiffeConstants.CLIENT_ASSERTION_TYPE);

        String trustedDomain = config.getTrustDomain();

        JsonWebToken token = validator.getState().getToken();
        if (!token.getSubject().startsWith(trustedDomain + "/")) {
            throw new RuntimeException("Invalid trust-domain");
        }

        return validator.validate();
    }

    private boolean verifySignature(AbstractJWTClientValidator validator) {
        try {
            String bundleEndpoint = config.getBundleEndpoint();
            JWSInput jws = validator.getState().getJws();
            JWSHeader header = jws.getHeader();
            String kid = header.getKeyId();
            String alg = header.getRawAlgorithm();

            String modelKey = PublicKeyStorageUtils.getIdpModelCacheKey(validator.getContext().getRealm().getId(), config.getInternalId());

            PublicKeyStorageProvider keyStorage = session.getProvider(PublicKeyStorageProvider.class);
            KeyWrapper publicKey = keyStorage.getPublicKey(modelKey, kid, alg, new SpiffeBundleEndpointLoader(session, bundleEndpoint));

            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
            if (signatureProvider == null) {
                LOGGER.debugf("Failed to verify token, signature provider not found for algorithm %s", alg);
                return false;
            }

            return signatureProvider.verifier(publicKey).verify(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8), jws.getSignature());
        } catch (Exception e) {
            LOGGER.debug("Failed to verify token signature", e);
            return false;
        }
    }

    @Override
    public void close() {
    }

    @Override
    public void preprocessFederatedIdentity(IAMShieldSession session, RealmModel realm, BrokeredIdentityContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void importNewUser(IAMShieldSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void updateBrokeredUser(IAMShieldSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Response retrieveToken(IAMShieldSession session, FederatedIdentityModel identity) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void backchannelLogout(IAMShieldSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Response keycloakInitiatedBrowserLogout(IAMShieldSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Response export(UriInfo uriInfo, RealmModel realm, String format) {
        throw new UnsupportedOperationException();
    }

    @Override
    public IdentityProviderDataMarshaller getMarshaller() {
        throw new UnsupportedOperationException();
    }
}
