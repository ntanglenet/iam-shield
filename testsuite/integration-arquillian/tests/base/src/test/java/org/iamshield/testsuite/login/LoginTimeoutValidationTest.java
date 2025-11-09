/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.login;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserManager;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.services.managers.ClientSessionCode;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.arquillian.annotation.ModelTest;

public class LoginTimeoutValidationTest extends AbstractTestRealmIAMShieldTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {

    }

    
    @Before
    public  void before() {
        testingClient.server().run( session -> {
            RealmModel realm = session.realms().getRealmByName("test");
            session.users().addUser(realm, "user1");
        });
    }
    

    @After
    public void after() {
        testingClient.server().run( session -> {
            RealmModel realm = session.realms().getRealmByName("test");
            session.sessions().removeUserSessions(realm);
            UserModel user1 = session.users().getUserByUsername(realm, "user1");

            UserManager um = new UserManager(session);
            if (user1 != null) {
                um.removeUser(realm, user1);
            }
        });
    }
    

    @Test
    @ModelTest
    public  void testIsLoginTimeoutValid(IAMShieldSession keycloakSession) {
        
        RealmModel realm = keycloakSession.realms().getRealmByName("test");
        UserSessionModel userSession =
            keycloakSession.sessions().createUserSession(
                                                 null, realm,
                                                 keycloakSession.users().getUserByUsername(realm, "user1"),
                                                 "user1", "127.0.0.1", "form", true, null, null,
                                                 UserSessionModel.SessionPersistenceState.PERSISTENT);
        ClientModel client = realm.getClientByClientId("account");
        AuthenticationSessionModel authSession = keycloakSession.authenticationSessions().createRootAuthenticationSession(realm)
            .createAuthenticationSession(client);
        ClientSessionCode clientSessionCode = new ClientSessionCode(keycloakSession, realm, authSession);

        /*
         * KEYCLOAK-10636 Large Login timeout causes login failure
         * realm > Realm setting > Tokens > Login timeout
         */
        int accessCodeLifespanLoginOrig = realm.getAccessCodeLifespanLogin(); // Login timeout
        realm.setAccessCodeLifespanLogin(Integer.MAX_VALUE);
        Assert.assertTrue("Login validataion with large Login Timeout failed",
                          clientSessionCode.isActionActive(ClientSessionCode.ActionType.LOGIN));
        realm.setAccessCodeLifespanLogin(accessCodeLifespanLoginOrig);

        /*
         * KEYCLOAK-10637 Large Login Action timeout causes login failure
         * realm > Realm setting > Tokens > Login Action timeout
         */
        int accessCodeLifespanUserActionOrig = realm.getAccessCodeLifespanUserAction(); // Login Action timeout
        realm.setAccessCodeLifespanUserAction(Integer.MAX_VALUE);
        Assert.assertTrue("Login validataion with large Login Action Timeout failed",
                          clientSessionCode.isActionActive(ClientSessionCode.ActionType.USER));
        realm.setAccessCodeLifespanUserAction(accessCodeLifespanUserActionOrig);
    }
}
