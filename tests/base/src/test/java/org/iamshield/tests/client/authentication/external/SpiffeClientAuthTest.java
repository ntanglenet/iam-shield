package org.iamshield.tests.client.authentication.external;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.iamshield.authentication.authenticators.client.FederatedJWTClientAuthenticator;
import org.iamshield.broker.spiffe.SpiffeConstants;
import org.iamshield.broker.spiffe.SpiffeIdentityProviderConfig;
import org.iamshield.broker.spiffe.SpiffeIdentityProviderFactory;
import org.iamshield.common.Profile;
import org.iamshield.common.util.Time;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.representations.JsonWebToken;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.oauth.OAuthIdentityProvider;
import org.iamshield.testframework.oauth.OAuthIdentityProviderConfig;
import org.iamshield.testframework.oauth.OAuthIdentityProviderConfigBuilder;
import org.iamshield.testframework.oauth.annotations.InjectOAuthIdentityProvider;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.RealmConfig;
import org.iamshield.testframework.realm.RealmConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testsuite.util.IdentityProviderBuilder;

@IAMShieldIntegrationTest(config = SpiffeClientAuthTest.SpiffeServerConfig.class)
@TestMethodOrder(MethodOrderer.MethodName.class)
public class SpiffeClientAuthTest extends AbstractFederatedClientAuthTest {

    private static final String INTERNAL_CLIENT_ID = "myclient";
    private static final String EXTERNAL_CLIENT_ID = "spiffe://mytrust-domain/myclient";
    private static final String IDP_ALIAS = "spiffe-idp";
    private static final String TRUST_DOMAIN = "spiffe://mytrust-domain";
    private static final String BUNDLE_ENDPOINT = "http://127.0.0.1:8500/idp/jwks";

    @InjectRealm(config = ExernalClientAuthRealmConfig.class)
    protected ManagedRealm realm;

    @InjectOAuthIdentityProvider(config = SpiffeIdpConfig.class)
    OAuthIdentityProvider identityProvider;

    public SpiffeClientAuthTest() {
        super(null, INTERNAL_CLIENT_ID, EXTERNAL_CLIENT_ID);
    }

    @Test
    public void testInvalidConfig() {
        testInvalidConfig("with-port:8080", "https://localhost");
        testInvalidConfig("with-spiffe-scheme", "https://localhost");
        testInvalidConfig("valid", "invalid-url");
    }

    @Test
    public void testInvalidTrustDomain() {
        realm.updateIdentityProviderWithCleanup(IDP_ALIAS, rep -> {
            rep.getConfig().put(IdentityProviderModel.ISSUER, "spiffe://different-domain");
        });

        JsonWebToken jwt = createDefaultToken();
        assertFailure(doClientGrant(jwt));
        assertFailure(null, null, jwt.getSubject(), jwt.getId(), "client_not_found", events.poll());
    }

    @Test
    public void testReuse() {
        JsonWebToken jwt = createDefaultToken();
        assertSuccess(INTERNAL_CLIENT_ID, doClientGrant(jwt));
        assertSuccess(INTERNAL_CLIENT_ID, jwt.getId(), null, EXTERNAL_CLIENT_ID, events.poll());
        assertSuccess(INTERNAL_CLIENT_ID, doClientGrant(jwt));
        assertSuccess(INTERNAL_CLIENT_ID, jwt.getId(), null, EXTERNAL_CLIENT_ID, events.poll());
    }

    @Override
    protected OAuthIdentityProvider getIdentityProvider() {
        return identityProvider;
    }

    @Override
    protected JsonWebToken createDefaultToken() {
        JsonWebToken token = new JsonWebToken();
        token.id(null);
        token.audience(oAuthClient.getEndpoints().getIssuer());
        token.exp((long) (Time.currentTime() + 300));
        token.subject(EXTERNAL_CLIENT_ID);
        return token;
    }

    private void testInvalidConfig(String trustDomain, String bundleEndpoint) {
        IdentityProviderRepresentation idp = IdentityProviderBuilder.create().providerId(SpiffeIdentityProviderFactory.PROVIDER_ID)
                .alias("another")
                .setAttribute(IdentityProviderModel.ISSUER, trustDomain)
                .setAttribute(SpiffeIdentityProviderConfig.BUNDLE_ENDPOINT_KEY, bundleEndpoint).build();

        try (Response r = realm.admin().identityProviders().create(idp)) {
            Assertions.assertEquals(400, r.getStatus());
        }
    }

    @Override
    protected String getClientAssertionType() {
        return SpiffeConstants.CLIENT_ASSERTION_TYPE;
    }

    public static class SpiffeServerConfig extends ClientAuthIdpServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            return super.configure(config).features(Profile.Feature.SPIFFE);
        }
    }

    public static class SpiffeIdpConfig implements OAuthIdentityProviderConfig {

        @Override
        public OAuthIdentityProviderConfigBuilder configure(OAuthIdentityProviderConfigBuilder config) {
            return config.spiffe();
        }
    }

    public static class ExernalClientAuthRealmConfig implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            realm.identityProvider(
                    IdentityProviderBuilder.create()
                            .providerId(SpiffeIdentityProviderFactory.PROVIDER_ID)
                            .alias(IDP_ALIAS)
                            .setAttribute(IdentityProviderModel.ISSUER, TRUST_DOMAIN)
                            .setAttribute(SpiffeIdentityProviderConfig.BUNDLE_ENDPOINT_KEY, BUNDLE_ENDPOINT)
                            .build());

            realm.addClient(INTERNAL_CLIENT_ID)
                    .serviceAccountsEnabled(true)
                    .authenticatorType(FederatedJWTClientAuthenticator.PROVIDER_ID)
                    .attribute(FederatedJWTClientAuthenticator.JWT_CREDENTIAL_ISSUER_KEY, IDP_ALIAS)
                    .attribute(FederatedJWTClientAuthenticator.JWT_CREDENTIAL_SUBJECT_KEY, EXTERNAL_CLIENT_ID);

            return realm;
        }
    }

}
