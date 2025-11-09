/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.tests.admin;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.Config;
import org.iamshield.OAuth2Constants;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.ClientResource;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.common.Profile;
import org.iamshield.cookie.CookieType;
import org.iamshield.events.EventType;
import org.iamshield.models.AdminRoles;
import org.iamshield.models.Constants;
import org.iamshield.models.ImpersonationSessionNote;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.ErrorRepresentation;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testframework.admin.AdminClientFactory;
import org.iamshield.testframework.annotations.InjectAdminClientFactory;
import org.iamshield.testframework.annotations.InjectEvents;
import org.iamshield.testframework.annotations.InjectIAMShieldUrls;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.InjectUser;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.events.EventMatchers;
import org.iamshield.testframework.events.Events;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.TestApp;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectTestApp;
import org.iamshield.testframework.realm.ClientConfigBuilder;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.ManagedUser;
import org.iamshield.testframework.realm.RealmConfig;
import org.iamshield.testframework.realm.RealmConfigBuilder;
import org.iamshield.testframework.realm.UserConfig;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.server.IAMShieldUrls;
import org.iamshield.testframework.ui.annotations.InjectPage;
import org.iamshield.testframework.ui.annotations.InjectWebDriver;
import org.iamshield.testframework.ui.page.LoginPage;
import org.iamshield.tests.utils.admin.ApiUtil;
import org.iamshield.testsuite.util.CredentialBuilder;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * Tests Undertow Adapter
 *
 * @author <a href="mailto:bburke@redhat.com">Bill Burke</a>
 */
@IAMShieldIntegrationTest(config = ImpersonationTest.ImpersonationTestServerConfig.class)
public class ImpersonationTest {

    @InjectRealm(ref = "test", config = ImpersonationTestRealmConfig.class)
    ManagedRealm managedRealm;

    @InjectUser(ref = "test-user", realmRef = "test", config = TestUserConfig.class)
    ManagedUser managedUser;

    @InjectRealm(ref = "master", attachTo = "master")
    ManagedRealm masterRealm;

    @InjectAdminClientFactory
    AdminClientFactory clientFactory;

    @InjectRunOnServer(realmRef = "test")
    RunOnServerClient runOnServer;

    @InjectOAuthClient(realmRef = "test")
    OAuthClient oauth;

    @InjectTestApp
    TestApp testApp;

    @InjectIAMShieldUrls
    IAMShieldUrls keycloakUrls;

    @InjectWebDriver
    WebDriver driver;

    @InjectPage
    LoginPage loginPage;

    @InjectEvents(ref = "test-events", realmRef = "test")
    Events events;

    @Test
    public void testImpersonateByMasterAdmin() {
        // test that composite is set up right for impersonation role
        testSuccessfulImpersonation("admin", Config.getAdminRealm());
    }

    @Test
    public void testImpersonateByMasterImpersonator() {
        String userId;
        try (Response response = masterRealm.admin().users().create(UserConfigBuilder.create().username("master-impersonator").build())) {
            userId = ApiUtil.getCreatedId(response);
        }

        UserResource user = masterRealm.admin().users().get(userId);
        user.resetPassword(CredentialBuilder.create().password("password").build());

        ClientResource testRealmClient = ApiUtil.findClientByClientId(masterRealm.admin(), managedRealm.getName() + "-realm");

        List<RoleRepresentation> roles = new LinkedList<>();
        roles.add(ApiUtil.findClientRoleByName(testRealmClient, AdminRoles.VIEW_USERS).toRepresentation());
        roles.add(ApiUtil.findClientRoleByName(testRealmClient, AdminRoles.IMPERSONATION).toRepresentation());

        user.roles().clientLevel(testRealmClient.toRepresentation().getId()).add(roles);

        testSuccessfulImpersonation("master-impersonator", Config.getAdminRealm());

        masterRealm.admin().users().get(userId).remove();
    }

    @Test
    public void testImpersongetServiceAccountUserateByTestImpersonator() {
        testSuccessfulImpersonation("impersonator", managedRealm.getName());
    }

    @Test
    public void testImpersonateByTestAdmin() {
        // test that composite is set up right for impersonation role
        testSuccessfulImpersonation("realm-admin", managedRealm.getName());
    }

    @Test
    public void testImpersonateByTestBadImpersonator() {
        testForbiddenImpersonation("bad-impersonator", managedRealm.getName());
    }

    @Test
    public void testImpersonationFailsForDisabledUser() {
        UserResource impersonatedUserResource = managedRealm.admin().users().get(managedUser.getId());
        UserRepresentation impersonatedUserRepresentation = impersonatedUserResource.toRepresentation();
        impersonatedUserRepresentation.setEnabled(false);
        impersonatedUserResource.update(impersonatedUserRepresentation);
        try {
            testBadRequestImpersonation("impersonator", managedRealm.getName(), managedUser.getId(), managedRealm.getName(), "User is disabled");
        } finally {
            impersonatedUserRepresentation.setEnabled(true);
            impersonatedUserResource.update(impersonatedUserRepresentation);
        }
    }

    @Test
    public void testImpersonateByMastertBadImpersonator() {
        String userId;
        try (Response response = masterRealm.admin().users().create(UserConfigBuilder.create().username("master-bad-impersonator").build())) {
            userId = ApiUtil.getCreatedId(response);
        }
        masterRealm.admin().users().get(userId).resetPassword(CredentialBuilder.create().password("password").build());

        testForbiddenImpersonation("master-bad-impersonator", Config.getAdminRealm());

        masterRealm.admin().users().get(userId).remove();
    }


    // KEYCLOAK-5981
    @Test
    public void testImpersonationWorksWhenAuthenticationSessionExists() throws Exception {
        // Open the URL for the client (will redirect to IAMShield server AuthorizationEndpoint and create authenticationSession)
        oauth.openLoginForm();
        loginPage.assertCurrent();

        // Impersonate and get SSO cookie. Setup that cookie for webDriver
        for (Cookie cookie : testSuccessfulImpersonation("realm-admin", managedRealm.getName())) {
            driver.manage().addCookie(cookie);
        }

        // Open the URL again - should be directly redirected to the app due the SSO login
        oauth.openLoginForm();

        //KEYCLOAK-12783
        Assertions.assertTrue(Objects.requireNonNull(driver.getCurrentUrl()).contains(testApp.getRedirectionUri()));
    }

    // KEYCLOAK-17655
    @Test
    public void testImpersonationBySameRealmServiceAccount() throws Exception {
        // Create test client service account
        ClientRepresentation clientApp = ClientConfigBuilder.create()
                .clientId("service-account-cl")
                .secret("password")
                .serviceAccountsEnabled(true)
                .build();
        clientApp.setServiceAccountsEnabled(true);
        managedRealm.admin().clients().create(clientApp);

        UserRepresentation user = ApiUtil.findClientByClientId(managedRealm.admin(), "service-account-cl").getServiceAccountUser();
        user.setServiceAccountClientId("service-account-cl");

        // add impersonation roles
        ApiUtil.assignClientRoles(managedRealm.admin(), user.getId(), Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.IMPERSONATION);

        // Impersonation
        testSuccessfulServiceAccountImpersonation(user, managedRealm.getName());

        // test impersonation over the service account fails
        testBadRequestImpersonation("impersonator", managedRealm.getName(), user.getId(), managedRealm.getName(), "Service accounts cannot be impersonated");

        // Remove test client
        ApiUtil.findClientByClientId(managedRealm.admin(), "service-account-cl").remove();
    }
    @Test
    public void testImpersonationByMasterRealmServiceAccount() throws Exception {
        // Create test client service account
        ClientRepresentation clientApp = ClientConfigBuilder.create()
                .clientId("service-account-cl")
                .secret("password")
                .serviceAccountsEnabled(true)
                .build();
        masterRealm.admin().clients().create(clientApp);

        UserRepresentation user = ApiUtil.findClientByClientId(masterRealm.admin(), "service-account-cl").getServiceAccountUser();
        user.setServiceAccountClientId("service-account-cl");

        // add impersonation roles
        ApiUtil.assignRealmRoles(masterRealm.admin(), user.getId(), "admin");

        // Impersonation
        testSuccessfulServiceAccountImpersonation(user, masterRealm.getName());

        // Remove test client
        ApiUtil.findClientByClientId(masterRealm.admin(), "service-account-cl").remove();
    }

    // Return the SSO cookie from the impersonated session
    private Set<Cookie> testSuccessfulImpersonation(String admin, String adminRealm) {
        // Login adminClient
        try (IAMShield client = login(admin, adminRealm)) {
            // Impersonate
            return impersonate(client, admin, adminRealm);
        }
    }

    private Set<Cookie> impersonate(IAMShield adminClient, String admin, String adminRealm) {
        BasicCookieStore cookieStore = new BasicCookieStore();
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build()) {

            HttpUriRequest req = RequestBuilder.post()
                    .setUri(keycloakUrls.getBase() + "/admin/realms/test/users/" + managedUser.getId() + "/impersonation")
                    .addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + adminClient.tokenManager().getAccessTokenString())
                    .build();

            HttpResponse res = httpClient.execute(req);
            String resBody = EntityUtils.toString(res.getEntity());

            Assertions.assertNotNull(resBody);
            Assertions.assertTrue(resBody.contains("redirect"));

            EventRepresentation event = events.poll();
            Assertions.assertEquals(event.getType(), EventType.IMPERSONATE.toString());
            MatcherAssert.assertThat(event.getSessionId(), EventMatchers.isUUID());
            Assertions.assertEquals(event.getUserId(), managedUser.getId());
            Assertions.assertTrue(event.getDetails().values().stream().anyMatch(f -> f.equals(admin)));
            Assertions.assertTrue(event.getDetails().values().stream().anyMatch(f -> f.equals(adminRealm)));

            String testRealm = managedRealm.getName();
            // Fetch user session notes
            final String userId = managedUser.getId();
            final UserSessionNotesHolder notesHolder = runOnServer.fetch(session -> {
                final RealmModel realm = session.realms().getRealmByName(testRealm);
                final UserModel user = session.users().getUserById(realm, userId);
                final UserSessionModel userSession = session.sessions().getUserSessionsStream(realm, user).filter(u -> u.getNotes().containsValue(admin)).findFirst().get();
                return new UserSessionNotesHolder(userSession.getNotes());
            }, UserSessionNotesHolder.class);

            // Check impersonation details
            final Map<String, String> notes = notesHolder.getNotes();
            Assertions.assertNotNull(notes.get(ImpersonationSessionNote.IMPERSONATOR_ID.toString()));
            Assertions.assertEquals(admin, notes.get(ImpersonationSessionNote.IMPERSONATOR_USERNAME.toString()));

            Set<Cookie> cookies = cookieStore.getCookies().stream()
                    .filter(c -> c.getName().startsWith(CookieType.IDENTITY.getName()))
                    .map(c -> new Cookie(c.getName(), c.getValue(), c.getDomain(), c.getPath(), c.getExpiryDate(), c.isSecure(), true))
                    .collect(Collectors.toSet());

            Assertions.assertNotNull(cookies);
            MatcherAssert.assertThat(cookies, is(not(empty())));
            httpClient.close();

            return cookies;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void testForbiddenImpersonation(String admin, String adminRealm) {
        try (IAMShield client = createAdminClient(adminRealm, establishClientId(adminRealm), admin)) {
            client.realms().realm(managedRealm.getName()).users().get(managedUser.getId()).impersonate();
            Assertions.fail("Expected ClientErrorException wasn't thrown.");
        } catch (ClientErrorException e) {
            MatcherAssert.assertThat(e.getMessage(), containsString("403 Forbidden"));
        }
    }

    private void testBadRequestImpersonation(String admin, String adminRealm, String impersonatedId,
            String impersonatedRealm, String errorExpected) {
        try (IAMShield client = createAdminClient(adminRealm, establishClientId(adminRealm), admin)) {
            client.realms().realm(impersonatedRealm).users().get(impersonatedId).impersonate();
            Assertions.fail("Expected ClientErrorException wasn't thrown.");
        } catch (ClientErrorException e) {
            Assertions.assertEquals(Response.Status.BAD_REQUEST, e.getResponse().getStatusInfo());
            ErrorRepresentation error = e.getResponse().readEntity(ErrorRepresentation.class);
            Assertions.assertEquals(errorExpected, error.getErrorMessage());
        }
    }


    private String establishClientId(String realm) {
        return realm.equals("master") ? Constants.ADMIN_CLI_CLIENT_ID : "myclient";
    }

    private IAMShield createAdminClient(String realm, String clientId, String username) {
        String password = username.equals("admin") ? "admin" : "password";

        return clientFactory.create()
                .realm(realm)
                .username(username)
                .password(password)
                .clientId(clientId)
                .grantType(OAuth2Constants.PASSWORD).build();
    }

    private IAMShield login(String username, String realm) {
        String clientId = establishClientId(realm);
        IAMShield client = createAdminClient(realm, clientId, username);

        client.tokenManager().grantToken();
        // only poll for LOGIN event if realm is not master
        // - since for master testing event listener is not installed
        if (!realm.equals("master")) {
            EventRepresentation e = events.poll();
            Assertions.assertEquals(EventType.LOGIN.toString(), e.getType(), "Event type");
            Assertions.assertEquals(clientId, e.getClientId(), "Client ID");
        }
        return client;
    }


    // Return the SSO cookie from the impersonated session
    private Set<Cookie> testSuccessfulServiceAccountImpersonation(UserRepresentation serviceAccount, String serviceAccountRealm) {
        // Login adminClient
        try (IAMShield client = loginServiceAccount(serviceAccount, serviceAccountRealm)) {
            // Impersonate test-user with service account
            return impersonateServiceAccount(client);
        }
    }

    private IAMShield loginServiceAccount(UserRepresentation serviceAccount, String serviceAccountRealm) {
        IAMShield client = createServiceAccountClient(serviceAccountRealm, serviceAccount);
        // get token
        client.tokenManager().getAccessToken();
        return client;
    }

    private IAMShield createServiceAccountClient(String serviceAccountRealm, UserRepresentation serviceAccount) {
        return clientFactory.create().realm(serviceAccountRealm).clientId(serviceAccount.getServiceAccountClientId()).clientSecret("password").grantType(OAuth2Constants.CLIENT_CREDENTIALS).build();
    }

    private Set<Cookie> impersonateServiceAccount(IAMShield adminClient) {
        BasicCookieStore cookieStore = new BasicCookieStore();
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build()) {

            HttpUriRequest req = RequestBuilder.post()
                    .setUri(keycloakUrls.getBase() + "/admin/realms/test/users/" + managedUser.getId() + "/impersonation")
                    .addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + adminClient.tokenManager().getAccessTokenString())
                    .build();

            HttpResponse res = httpClient.execute(req);
            String resBody = EntityUtils.toString(res.getEntity());

            Assertions.assertNotNull(resBody);
            Assertions.assertTrue(resBody.contains("redirect"));
            Set<Cookie> cookies = cookieStore.getCookies().stream()
                    .filter(c -> c.getName().startsWith(CookieType.IDENTITY.getName()))
                    .map(c -> new Cookie(c.getName(), c.getValue(), c.getDomain(), c.getPath(), c.getExpiryDate(), c.isSecure(), true))
                    .collect(Collectors.toSet());

            Assertions.assertNotNull(cookies);
            MatcherAssert.assertThat(cookies, is(not(empty())));
            httpClient.close();

            return cookies;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static class UserSessionNotesHolder {
        private Map<String, String> notes = new HashMap<>();

        public UserSessionNotesHolder() {
        }

        public UserSessionNotesHolder(final Map<String, String> notes) {
            this.notes = notes;
        }

        public void setNotes(final Map<String, String> notes) {
            this.notes = notes;
        }

        public Map<String, String> getNotes() {
            return notes;
        }
    }

    public static class ImpersonationTestServerConfig implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder server) {
            server.features(Profile.Feature.IMPERSONATION);
            return server;
        }
    }

    private static class ImpersonationTestRealmConfig implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder config) {
            config.addClient("myclient").clientId("myclient")
                    .publicClient(true).directAccessGrantsEnabled(true);

            config.addUser("realm-admin")
                    .password("password").name("My", "Test Admin")
                    .email("my-test-admin@email.org").emailVerified(true)
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.REALM_ADMIN);
            config.addUser("impersonator")
                    .password("password").name("My", "Test Impersonator")
                    .email("my-test-impersonator@email.org").emailVerified(true)
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.IMPERSONATION)
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.VIEW_USERS);
            config.addUser("bad-impersonator")
                    .password("password").name("My", "Test Bad Impersonator")
                    .email("my-test-bad-impersonator@email.org").emailVerified(true)
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.MANAGE_USERS);

            return config;
        }
    }

    private static class TestUserConfig implements UserConfig {

        @Override
        public UserConfigBuilder configure(UserConfigBuilder user) {
            user.username("test-user");
            user.password("password");
            user.name("My", "Test");
            user.email("test@email.org");
            user.emailVerified(true);

            return user;
        }
    }
}
