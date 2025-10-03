/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.iamshield.testsuite.oidc;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.iamshield.admin.client.resource.ClientResource;
import org.iamshield.authentication.authenticators.client.JWTClientAuthenticator;
import org.iamshield.events.Details;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.AbstractIAMShieldTest;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.admin.ApiUtil;
import org.iamshield.testsuite.util.ClientManager;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.iamshield.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OIDCPublicClientTest extends AbstractIAMShieldTest {

    @Rule
    public AssertEvents events = new AssertEvents(this);


    @Override
    public void beforeAbstractIAMShieldTest() throws Exception {
        super.beforeAbstractIAMShieldTest();
    }

    @Before
    public void clientConfiguration() {
        ClientManager.realm(adminClient.realm("test")).clientId("test-app").directAccessGrant(true);
        /*
         * Configure the default client ID. Seems like OAuthClient is keeping the state of clientID
         * For example: If some test case configure oauth.clientId("sample-public-client"), other tests
         * will faile and the clientID will always be "sample-public-client
         * @see AccessTokenTest#testAuthorizationNegotiateHeaderIgnored()
         */
        oauth.clientId("test-app");
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        testRealms.add(realm);
    }


    // KEYCLOAK-18258
    @Test
    public void accessTokenRequest() throws Exception {
        // Update client to use custom client authenticator
        ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realms().realm("test"), "test-app");
        ClientRepresentation clientRep = clientResource.toRepresentation();
        clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
        clientResource.update(clientRep);

        // Switch client to public client now
        clientRep = clientResource.toRepresentation();
        Assert.assertEquals(JWTClientAuthenticator.PROVIDER_ID, clientRep.getClientAuthenticatorType());
        clientRep.setPublicClient(true);
        clientResource.update(clientRep);

        // It should be possible to authenticate
        oauth.doLogin("test-user@localhost", "password");

        EventRepresentation loginEvent = events.expectLogin().assertEvent();

        String sessionId = loginEvent.getSessionId();
        String codeId = loginEvent.getDetails().get(Details.CODE_ID);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.doAccessTokenRequest(code);

        assertEquals(200, response.getStatusCode());
        assertNotNull(response.getAccessToken());
        EventRepresentation event = events.expectCodeToToken(codeId, sessionId).assertEvent();
    }

}
