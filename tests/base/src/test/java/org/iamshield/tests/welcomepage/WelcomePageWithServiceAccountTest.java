package org.iamshield.tests.welcomepage;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.iamshield.tests.welcomepage.WelcomePageTest.assertOnAdminConsole;
import static org.iamshield.tests.welcomepage.WelcomePageTest.getPublicServerUrl;

import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.admin.client.resource.UsersResource;
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
import org.iamshield.testframework.ui.page.WelcomePage;
import org.openqa.selenium.WebDriver;

@IAMShieldIntegrationTest(config = WelcomePageWithServiceAccountTest.WelcomePageWithServiceAccountTestConfig.class)
@TestMethodOrder(OrderAnnotation.class)
public class WelcomePageWithServiceAccountTest {

    // force the creation of a new server
    static class WelcomePageWithServiceAccountTestConfig implements IAMShieldServerConfig {
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

    @Test
    @Order(1)
    public void localAccessWithServiceAccount() {
        // get rid of the admin user - the service account should still exist
        RealmResource masterRealm = adminClient.realms().realm("master");
        UsersResource users = masterRealm.users();
        masterRealm.users().searchByUsername(Config.getAdminUsername(), true).stream().findFirst().ifPresent(admin -> users.delete(admin.getId()));

        welcomePage.navigateTo();

        assertOnAdminConsole(driver);
    }

    @Test
    @Order(2)
    public void remoteAccessWithServiceAccount() throws Exception {
        driver.get(getPublicServerUrl().toString());

        assertOnAdminConsole(driver);
    }

    @Test
    @Order(3)
    public void createAdminUser() throws Exception {
        // should fail because the service account user already exists
        assertFalse(runOnServer.fetch(session -> new ApplianceBootstrap(session)
                .createMasterRealmAdminUser(Config.getAdminUsername(), Config.getAdminPassword(), true, true), Boolean.class));

        // should succeed as a non-initial user
        assertTrue(runOnServer.fetch(session -> new ApplianceBootstrap(session)
                .createMasterRealmAdminUser(Config.getAdminUsername(), Config.getAdminPassword(), true, false), Boolean.class));
    }

}
