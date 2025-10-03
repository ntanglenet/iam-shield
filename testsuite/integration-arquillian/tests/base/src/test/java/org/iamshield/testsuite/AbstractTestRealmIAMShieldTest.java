/*
 * Copyright 2016 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.iamshield.testsuite;

import org.junit.Before;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.common.util.reflections.Reflections;
import org.iamshield.events.Details;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.representations.IDToken;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;

import java.lang.reflect.Field;
import java.util.List;

import static org.iamshield.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * This class provides loading of the testRealm called "test".  It also
 * provides a few utility methods for the testRealm.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public abstract class AbstractTestRealmIAMShieldTest extends AbstractIAMShieldTest {
    public static final String TEST_REALM_NAME = "test";

    protected RealmResource testRealm() {
        return adminClient.realm(TEST_REALM_NAME);
    }

    protected UserRepresentation findUser(String userNameOrEmail) {
        List<UserRepresentation> repList = testRealm().users().search(userNameOrEmail, -1, -1);
        if (repList.size() != 1) throw new IllegalStateException("User search expected one result. Found " + repList.size() + " users.");
        return repList.get(0);
    }

    protected void updateUser(UserRepresentation user) {
        testRealm().users().get(user.getId()).update(user);
    }

    protected ClientRepresentation findTestApp(RealmRepresentation testRealm) {
        for (ClientRepresentation client : testRealm.getClients()) {
            if (client.getClientId().equals("test-app")) return client;
        }

        return null;
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        log.debug("Adding test realm for import from testrealm.json");
        RealmRepresentation testRealm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);

        testRealms.add(testRealm);

        configureTestRealm(testRealm);
    }


    @Before
    @Override
    public void beforeAbstractIAMShieldTest() throws Exception {
        deleteCookies();
        super.beforeAbstractIAMShieldTest();
    }

    public void deleteCookies() {
        deleteAllCookiesForRealm("test");
    }

    /**
     * This allows a subclass to change the configuration of the testRealm before
     * it is imported.  This method will be called prior to any @Before methods
     * in the subclass.
     *
     * @param testRealm The realm read from /testrealm.json.
     */
    public abstract void configureTestRealm(RealmRepresentation testRealm);


    protected IDToken sendTokenRequestAndGetIDToken(EventRepresentation loginEvent) {

        AccessTokenResponse response = sendTokenRequestAndGetResponse(loginEvent);
        return oauth.verifyIDToken(response.getIdToken());
    }

    protected AccessTokenResponse sendTokenRequestAndGetResponse(EventRepresentation loginEvent) {

        Field eventsField = Reflections.findDeclaredField(this.getClass(), "events");
        AssertEvents events = null;
        if(eventsField != null) {
            events = Reflections.getFieldValue(eventsField, this, AssertEvents.class);
        }

        String sessionId = loginEvent.getSessionId();
        String codeId = loginEvent.getDetails().get(Details.CODE_ID);

        if(eventsField != null) {
            events.clear();
        }
        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.doAccessTokenRequest(code);

        Assert.assertEquals(200, response.getStatusCode());

        if (eventsField != null) {
            events.expectCodeToToken(codeId, sessionId).user(loginEvent.getUserId()).session(sessionId).assertEvent();
        }

        return response;
    }

    /** KEYCLOAK-12065 Inherit Client Connection from parent session **/
    public static IAMShieldSession inheritClientConnection(IAMShieldSession parentSession, IAMShieldSession currentSession) {
        currentSession.getContext().setConnection(parentSession.getContext().getConnection());
        return currentSession;
    }

    protected void afterAbstractIAMShieldTestRealmImport() {
        // Default empty implementation - subclasses can override if needed
    }
}
