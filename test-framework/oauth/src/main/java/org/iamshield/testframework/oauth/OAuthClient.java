package org.iamshield.testframework.oauth;

import org.apache.http.impl.client.CloseableHttpClient;
import org.iamshield.OAuth2Constants;
import org.iamshield.testframework.ui.page.LoginPage;
import org.iamshield.testsuite.util.oauth.AbstractOAuthClient;
import org.iamshield.testsuite.util.oauth.OAuthClientConfig;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.PageFactory;

public class OAuthClient extends AbstractOAuthClient<OAuthClient> {

    public OAuthClient(String baseUrl, CloseableHttpClient httpClient, WebDriver webDriver) {
        super(baseUrl, httpClient, webDriver);

        config = new OAuthClientConfig()
                .responseType(OAuth2Constants.CODE);
    }

    @Override
    public void fillLoginForm(String username, String password) {
        LoginPage loginPage = new LoginPage(driver);
        PageFactory.initElements(driver, loginPage);
        loginPage.fillLogin(username, password);
        loginPage.submit();
    }

    public void close() {
    }

}
