package org.iamshield.tests.welcomepage;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.URL;
import java.time.Duration;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.common.util.IAMShieldUriBuilder;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.services.managers.ApplianceBootstrap;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.config.Config;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.testframework.ui.annotations.InjectPage;
import org.iamshield.testframework.ui.annotations.InjectWebDriver;
import org.iamshield.testframework.ui.page.LoginPage;
import org.iamshield.testframework.ui.page.WelcomePage;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

@IAMShieldIntegrationTest(config = WelcomePageTest.WelcomePageTestConfig.class)
@TestMethodOrder(OrderAnnotation.class)
public class WelcomePageTest {

    // force the creation of a new server
    static class WelcomePageTestConfig implements IAMShieldServerConfig {
        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            return config;
        }
    }

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @InjectWebDriver
    WebDriver driver;

    @InjectAdminClient
    IAMShield adminClient;

    @InjectPage
    WelcomePage welcomePage;

    @InjectPage
    LoginPage loginPage;

    @Test
    @Order(1)
    public void localAccessNoAdminNorServiceAccount() {
        // get rid of the bootstrap admin user and client
        // it will get added back in subsequent tests
        var users = adminClient.realms().realm("master").users();
        users.searchByUsername(Config.getAdminUsername(), true).stream().findFirst().ifPresent(admin -> users.delete(admin.getId()));
        var clients = adminClient.realms().realm("master").clients();
        clients.findByClientId(Config.getAdminClientId()).stream().findFirst().ifPresent(client -> clients.delete(client.getId()));

        welcomePage.navigateTo();

        Assertions.assertEquals("Create an administrative user", welcomePage.getWelcomeMessage());
        Assertions.assertTrue(welcomePage.getWelcomeDescription().startsWith("To get started with IAMShield, you first create an administrative user"));
        Assertions.assertTrue(driver.getPageSource().contains("form"));
    }

    @Test
    @Order(2)
    public void remoteAccessNoAdmin() throws Exception {
        driver.get(getPublicServerUrl().toString());

        Assertions.assertEquals("Local access required", welcomePage.getWelcomeMessage());
        Assertions.assertTrue(welcomePage.getWelcomeDescription().startsWith("You will need local access to create the administrative user."));
        Assertions.assertFalse(driver.getPageSource().contains("form"));
    }

    @Test
    @Order(3)
    public void createAdminUser() {
        welcomePage.navigateTo();
        welcomePage.fillRegistration(Config.getAdminUsername(), Config.getAdminPassword());
        welcomePage.submit();

        Assertions.assertTrue(welcomePage.getPageAlert().contains("User created"));

        // re-establish the service account so that the admin client will work
        assertTrue(runOnServer.fetch(session -> new ApplianceBootstrap(session)
                .createTemporaryMasterRealmAdminService(Config.getAdminClientId(), Config.getAdminClientSecret()), Boolean.class));

        adminClient.tokenManager().refreshToken();

        List<UserRepresentation> users = adminClient.realm("master").users().search(Config.getAdminUsername(), true);
        Assertions.assertEquals(1, users.size());
    }

    @Test
    @Order(4)
    public void localAccessWithAdmin() {
        welcomePage.navigateTo();

        assertOnAdminConsole(driver);
    }

    @Test
    @Order(5)
    public void remoteAccessWithAdmin() throws Exception {
        driver.get(getPublicServerUrl().toString());

        assertOnAdminConsole(driver);
    }

    @Test
    @Order(6)
    public void accessCreatedAdminAccount() throws MalformedURLException {
        welcomePage.navigateTo();

        // HtmlUnit does not support Admin Console as it uses JavaScript modules, so faking the redirect to login pages
        if (driver.getClass().equals(HtmlUnitDriver.class)) {
            driver.navigate().to(getFakeLoginRedirect());
        }

        loginPage.fillLogin(Config.getAdminUsername(), Config.getAdminPassword());
        loginPage.submit();

        Assertions.assertEquals("IAMShield Administration Console", driver.getTitle());
    }

    /**
     * Attempt to resolve the floating IP address. This is where Quarkus
     * will be accessible.
     *
     * @return
     * @throws Exception
     */
    private static String getFloatingIpAddress() throws Exception {
        Enumeration<NetworkInterface> netInterfaces = NetworkInterface.getNetworkInterfaces();
        for (NetworkInterface ni : Collections.list(netInterfaces)) {
            Enumeration<InetAddress> inetAddresses = ni.getInetAddresses();
            for (InetAddress a : Collections.list(inetAddresses)) {
                if (!a.isLoopbackAddress() && a.isSiteLocalAddress()) {
                    return a.getHostAddress();
                }
            }
        }
        return null;
    }

    static URL getPublicServerUrl() throws Exception {
        String floatingIp = getFloatingIpAddress();
        if (floatingIp == null) {
            throw new RuntimeException("Could not determine floating IP address.");
        }
        return new URL("http", floatingIp, 8080, "");
    }

    static void assertOnAdminConsole(WebDriver driver) {
        new WebDriverWait(driver, Duration.ofSeconds(10)).until(d -> driver.getTitle().equals("IAMShield Administration Console") || driver.getTitle().equals("Sign in to IAMShield"));
    }

    private URL getFakeLoginRedirect() throws MalformedURLException {
        IAMShieldUriBuilder uriBuilder = IAMShieldUriBuilder.fromUri("http://localhost:8080/realms/master/protocol/openid-connect/auth");
        uriBuilder.queryParam("client_id", "security-admin-console");
        uriBuilder.queryParam("redirect_uri", "http://localhost:8080/admin/master/console/");
        uriBuilder.queryParam("state", "randomstate");
        uriBuilder.queryParam("response_mode", "query");
        uriBuilder.queryParam("response_type", "code");
        uriBuilder.queryParam("scope", "openid");
        uriBuilder.queryParam("nonce", "randomnonce");
        uriBuilder.queryParam("code_challenge", "UV90ZNinyGsxyNlz6A08FQzDXbA7NCjkrCZv7PgeVxA");
        uriBuilder.queryParam("code_challenge_method", "S256");
        return uriBuilder.build().toURL();
    }

}
