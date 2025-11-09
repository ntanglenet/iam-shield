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
package org.iamshield.testsuite.oauth;

import java.util.List;

import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.representations.AccessToken;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.AbstractIAMShieldTest;
import static org.iamshield.testsuite.admin.AbstractAdminTest.loadJson;
import static org.iamshield.testsuite.admin.ApiUtil.findUserByUsername;

import org.iamshield.testsuite.util.oauth.AccessTokenResponse;
import org.openqa.selenium.By;

/**
 * @author <a href="mailto:slawomir@dabek.name">Slawomir Dabek</a>
 */
public class AccessTokenNoEmailLoginTest extends AbstractIAMShieldTest {
    
    @Override
    public void beforeAbstractIAMShieldTest() throws Exception {
        super.beforeAbstractIAMShieldTest();
    }

    @Before
    public void clientConfiguration() {
        oauth.clientId("test-app");
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        realm.setLoginWithEmailAllowed(false);
        testRealms.add(realm);
    }
    
    @Test
    public void loginFormUsernameLabel() throws Exception {
        oauth.openLoginForm();
        
        assertEquals("Username", driver.findElement(By.xpath("//label[@for='username']")).getText());
    }

    @Test
    public void loginWithUsername() throws Exception {
        oauth.doLogin("non-duplicate-email-user", "password");

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.doAccessTokenRequest(code);

        assertEquals(200, response.getStatusCode());

        AccessToken token = oauth.verifyToken(response.getAccessToken());

        assertEquals(findUserByUsername(adminClient.realm("test"), "non-duplicate-email-user").getId(), token.getSubject());
        assertEquals("non-duplicate-email-user@localhost", token.getEmail());
    }

    @Test
    public void loginWithEmail() throws Exception {
        oauth.doLogin("non-duplicate-email-user@localhost", "password");
        
        assertEquals("Invalid username or password.", driver.findElement(By.className("kc-feedback-text")).getText());
    }
}
