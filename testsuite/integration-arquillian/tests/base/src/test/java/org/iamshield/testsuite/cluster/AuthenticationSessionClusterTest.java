/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.cluster;

import org.hamcrest.Matchers;
import org.infinispan.Cache;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.connections.infinispan.InfinispanUtil;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.services.managers.AuthenticationSessionManager;
import org.iamshield.sessions.StickySessionEncoderProvider;
import org.iamshield.sessions.StickySessionEncoderProviderFactory;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.pages.LoginPage;
import org.iamshield.testsuite.pages.LoginPasswordUpdatePage;
import org.iamshield.testsuite.pages.LoginUpdateProfilePage;
import org.iamshield.testsuite.util.oauth.OAuthClient;

import jakarta.ws.rs.core.UriBuilder;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.iamshield.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthenticationSessionClusterTest extends AbstractClusterTest {

    @Page
    protected LoginPage loginPage;

    @Page
    protected LoginPasswordUpdatePage updatePasswordPage;


    @Page
    protected LoginUpdateProfilePage updateProfilePage;

    @Page
    protected AppPage appPage;


    @Before
    public void setup() {
        try {
            adminClient.realm("test").remove();
        } catch (Exception ignore) {
        }

        RealmRepresentation testRealm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        adminClient.realms().create(testRealm);
    }

    @After
    public void after() {
        adminClient.realm("test").remove();
    }


    @Test
    public void testAuthSessionCookieWithAttachedRoute() throws Exception {
        OAuthClient oAuthClient = oauth;
        oAuthClient.baseUrl(UriBuilder.fromUri(backendNode(0).getUriBuilder().build() + "/auth").build("test").toString());

        String testAppLoginNode1URL = oAuthClient.loginForm().build();

        Set<String> visitedRoutes = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            driver.navigate().to(testAppLoginNode1URL);
            String authSessionCookie = AuthenticationSessionFailoverClusterTest.getAuthSessionCookieValue(driver);

            Assert.assertNotEquals( -1, authSessionCookie.indexOf("."));
            String route = authSessionCookie.substring(authSessionCookie.indexOf(".") + 1);
            visitedRoutes.add(route);

            // Drop all cookies before continue
            driver.manage().deleteAllCookies();
        }

        assertThat(visitedRoutes, Matchers.containsInAnyOrder(Matchers.startsWith("node1"), Matchers.startsWith("node2")));
    }


    @Test
    public void testAuthSessionCookieWithoutRoute() throws Exception {
        OAuthClient oAuthClient = oauth;
        oAuthClient.baseUrl(UriBuilder.fromUri(backendNode(0).getUriBuilder().build() + "/auth").build("test").toString());

        String testAppLoginNode1URL = oAuthClient.loginForm().build();

        // Disable route on backend server
        getTestingClientFor(backendNode(0)).server().run(session -> {
            StickySessionEncoderProviderFactory factory = (StickySessionEncoderProviderFactory) session.getIAMShieldSessionFactory().getProviderFactory(StickySessionEncoderProvider.class);
            factory.setShouldAttachRoute(false);
        });

        // Test routes
        for (int i = 0; i < 20; i++) {
            driver.navigate().to(testAppLoginNode1URL);
            String authSessionCookie = AuthenticationSessionFailoverClusterTest.getAuthSessionCookieValue(driver);

            Assert.assertEquals(authSessionCookie.indexOf("."), -1);

            // Drop all cookies before continue
            driver.manage().deleteAllCookies();

            // Check that route owner is always node1
            getTestingClientFor(backendNode(0)).server().run(session -> {
                Cache authSessionCache = session.getProvider(InfinispanConnectionProvider.class).getCache(InfinispanConnectionProvider.AUTHENTICATION_SESSIONS_CACHE_NAME);
                String decodedAuthSessionId = new AuthenticationSessionManager(session).decodeBase64AndValidateSignature(authSessionCookie, false);
                String keyOwner = InfinispanUtil.getTopologyInfo(session).getRouteName(authSessionCache, decodedAuthSessionId);
                Assert.assertTrue(keyOwner.startsWith("node1"));
            });
        }

        // Revert route on backend server
        getTestingClientFor(backendNode(0)).server().run(session -> {
            StickySessionEncoderProviderFactory factory = (StickySessionEncoderProviderFactory) session.getIAMShieldSessionFactory().getProviderFactory(StickySessionEncoderProvider.class);
            factory.setShouldAttachRoute(true);
        });
    }
}
