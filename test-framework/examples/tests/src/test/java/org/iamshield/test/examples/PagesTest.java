package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.ui.annotations.InjectPage;
import org.iamshield.testframework.ui.annotations.InjectWebDriver;
import org.iamshield.testframework.ui.page.LoginPage;
import org.iamshield.testframework.ui.page.WelcomePage;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;

@IAMShieldIntegrationTest
public class PagesTest {

    @InjectAdminClient
    IAMShield adminClient;

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @InjectWebDriver
    WebDriver webDriver;

    @InjectPage
    WelcomePage welcomePage;

    @InjectPage
    LoginPage loginPage;

    @Test
    public void testLoginFromWelcome() {
        welcomePage.navigateTo();

        if (webDriver instanceof HtmlUnitDriver) {
            String pageId = webDriver.findElement(By.xpath("//body")).getAttribute("data-page-id");
            Assertions.assertEquals("admin", pageId);
            Assertions.assertTrue(webDriver.getCurrentUrl().endsWith("/admin/master/console/"));
        } else {
            loginPage.waitForPage();

            loginPage.assertCurrent();

            loginPage.fillLogin("admin", "admin");
            loginPage.submit();
        }

    }

}
