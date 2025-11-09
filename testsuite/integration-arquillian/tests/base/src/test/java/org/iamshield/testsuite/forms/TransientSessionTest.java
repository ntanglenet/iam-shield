/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.forms;

import org.junit.Rule;
import org.junit.Test;
import org.iamshield.models.UserSessionModel;
import org.iamshield.models.utils.DefaultAuthenticationFlows;
import org.iamshield.representations.AccessToken;
import org.iamshield.representations.RefreshToken;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.testsuite.AbstractChangeImportedUserPasswordsTest;
import org.iamshield.testsuite.Assert;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.util.FlowUtil;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.iamshield.models.AuthenticationExecutionModel.Requirement.REQUIRED;

/**
 * Test for transient user session
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TransientSessionTest extends AbstractChangeImportedUserPasswordsTest {

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Test
    public void loginSuccess() throws Exception {
        setUpDirectGrantFlowWithSetClientNoteAuthenticator();

        oauth.client("direct-grant", "password");

        // Signal that we want userSession to be transient
        AccessTokenResponse response = oauth.passwordGrantRequest("test-user@localhost", getPassword("test-user@localhost"))
                .param(SetClientNoteAuthenticator.PREFIX + AuthenticationManager.USER_SESSION_PERSISTENT_STATE, UserSessionModel.SessionPersistenceState.TRANSIENT.toString())
                .send();

        assertEquals(200, response.getStatusCode());

        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());

        // sessionState is available, but the session was transient and hence not really persisted on the server
        assertNotNull(accessToken.getSessionState());
        assertEquals(accessToken.getSessionState(), refreshToken.getSessionState());

        // Refresh will fail. There is no userSession on the server
        AccessTokenResponse refreshedResponse = oauth.doRefreshTokenRequest(response.getRefreshToken());
        Assert.assertNull(refreshedResponse.getAccessToken());
        assertNotNull(refreshedResponse.getError());
        Assert.assertEquals("Session not active", refreshedResponse.getErrorDescription());
    }

    private void setUpDirectGrantFlowWithSetClientNoteAuthenticator() {
        final String newFlowAlias = "directGrantCustom";
        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session).copyFlow(DefaultAuthenticationFlows.DIRECT_GRANT_FLOW, newFlowAlias));
        testingClient.server("test").run(session -> {
            FlowUtil.inCurrentRealm(session)
                    .selectFlow(newFlowAlias)
                    .addAuthenticatorExecution(REQUIRED, SetClientNoteAuthenticator.PROVIDER_ID)
                    .defineAsDirectGrantFlow();
        });
    }

}
