package org.iamshield.tests.admin.metric;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.testframework.annotations.InjectHttpClient;
import org.iamshield.testframework.annotations.InjectIAMShieldUrls;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.InjectUser;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.ManagedUser;
import org.iamshield.testframework.realm.UserConfig;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.server.IAMShieldUrls;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;
import org.iamshield.testsuite.util.oauth.AuthorizationEndpointResponse;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@IAMShieldIntegrationTest(config = PasswordValidationMetricCustomTagsTest.ServerConfigWithMetrics.class)
public class PasswordValidationMetricCustomTagsTest {

    @InjectUser(config = OAuthUserConfig.class)
    ManagedUser user;

    @InjectRealm
    ManagedRealm realm;

    @InjectOAuthClient
    OAuthClient oAuthClient;

    @InjectIAMShieldUrls
    IAMShieldUrls keycloakUrls;

    @InjectHttpClient
    HttpClient httpClient;

    Pattern passValidationRegex = Pattern.compile("keycloak_credentials_password_hashing_validations_total\\{realm=\"([^\"]+)\"} ([.0-9]*)");

    @Test
    void testValidAndInvalidPasswordValidation() throws IOException {
        runAuthorizationCodeFlow(user.getUsername(), "invalid_password", false);
        runAuthorizationCodeFlow(user.getUsername(), user.getPassword(), true);

        String metrics = EntityUtils.toString(httpClient.execute(new HttpGet(keycloakUrls.getMetric())).getEntity());
        Matcher matcher = passValidationRegex.matcher(metrics);

        Assertions.assertTrue(matcher.find());
        Assertions.assertEquals(realm.getName(), matcher.group(1));
        Assertions.assertEquals("2.0", matcher.group(2));
        Assertions.assertFalse(matcher.find());
    }

    private void runAuthorizationCodeFlow(String username, String password, boolean success) {
        AuthorizationEndpointResponse authorizationEndpointResponse = oAuthClient.doLogin(username, password);
        if (!success) {
            Assertions.assertFalse(authorizationEndpointResponse.isRedirected());
            return;
        }
        AccessTokenResponse accessTokenResponse = oAuthClient.doAccessTokenRequest(authorizationEndpointResponse.getCode());
        Assertions.assertTrue(accessTokenResponse.isSuccess());
    }

    public static class ServerConfigWithMetrics implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            return config
                    .option("metrics-enabled", "true")
                    .option("spi-credential-keycloak-password-validations-counter-tags", "realm");
        }
    }

    public static class OAuthUserConfig implements UserConfig {

        @Override
        public UserConfigBuilder configure(UserConfigBuilder user) {
            return user.name("First", "Last")
                    .email("test@local")
                    .password("password");
        }
    }
}
