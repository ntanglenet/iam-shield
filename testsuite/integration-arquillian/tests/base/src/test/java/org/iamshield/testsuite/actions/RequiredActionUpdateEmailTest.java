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
 */
package org.iamshield.testsuite.actions;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.iamshield.userprofile.UserProfileConstants.ROLE_USER;
import static org.iamshield.userprofile.UserProfileConstants.ROLE_ADMIN;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.iamshield.admin.client.resource.UserProfileResource;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.events.Details;
import org.iamshield.events.EventType;
import org.iamshield.models.UserModel;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.representations.idm.UserSessionRepresentation;
import org.iamshield.representations.userprofile.config.UPAttribute;
import org.iamshield.representations.userprofile.config.UPAttributePermissions;
import org.iamshield.representations.userprofile.config.UPConfig;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.util.oauth.OAuthClient;

public class RequiredActionUpdateEmailTest extends AbstractRequiredActionUpdateEmailTest {

    @Override
    protected void changeEmailUsingRequiredAction(String newEmail, boolean logoutOtherSessions) {
        loginPage.open();

        loginPage.login("test-user@localhost", "password");
        updateEmailPage.assertCurrent();
        if (logoutOtherSessions) {
            updateEmailPage.checkLogoutSessions();
        }
        Assert.assertEquals(logoutOtherSessions, updateEmailPage.isLogoutSessionsChecked());

        updateEmailPage.changeEmail(newEmail);
    }

    private void updateEmail(boolean logoutOtherSessions) {
        // login using another session
        configureRequiredActionsToUser("test-user@localhost");
        UserResource testUser = testRealm().users().get(findUser("test-user@localhost").getId());
        OAuthClient oauth2 = oauth.newConfig().driver(driver2);;
        oauth2.doLogin("test-user@localhost", "password");
        EventRepresentation event1 = events.expectLogin().assertEvent();
        assertEquals(1, testUser.getUserSessions().size());

        // add the action and change it
        configureRequiredActionsToUser("test-user@localhost", UserModel.RequiredAction.UPDATE_EMAIL.name());
        changeEmailUsingRequiredAction("new@localhost", logoutOtherSessions);

        if (logoutOtherSessions) {
            events.expectLogout(event1.getSessionId())
                    .detail(Details.LOGOUT_TRIGGERED_BY_REQUIRED_ACTION, UserModel.RequiredAction.UPDATE_EMAIL.name())
                    .assertEvent();
        }

        events.expectRequiredAction(EventType.UPDATE_EMAIL).detail(Details.PREVIOUS_EMAIL, "test-user@localhost")
                .detail(Details.UPDATED_EMAIL, "new@localhost").assertEvent();
        assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());

        EventRepresentation event2 = events.expectLogin().assertEvent();
        List<UserSessionRepresentation> sessions = testUser.getUserSessions();
        if (logoutOtherSessions) {
            assertEquals(1, sessions.size());
            assertEquals(event2.getSessionId(), sessions.iterator().next().getId());
        } else {
            assertEquals(2, sessions.size());
            MatcherAssert.assertThat(sessions.stream().map(UserSessionRepresentation::getId).collect(Collectors.toList()),
                    Matchers.containsInAnyOrder(event1.getSessionId(), event2.getSessionId()));
        }

        // assert user is really updated in persistent store
        UserRepresentation user = ActionUtil.findUserWithAdminClient(adminClient, "test-user@localhost");
        assertEquals("new@localhost", user.getEmail());
        assertEquals("Tom", user.getFirstName());
        assertEquals("Brady", user.getLastName());
        assertFalse(user.getRequiredActions().contains(UserModel.RequiredAction.UPDATE_EMAIL.name()));
    }

    @Test
    public void updateEmailLogoutSessionsChecked() {
        updateEmail(true);
    }

    @Test
    public void updateEmailLogoutSessionsNotChecked() {
        updateEmail(false);
    }

    @Test
    public void updateEmailRequiredActionWhenEmailIsReadonly() {
        UserProfileResource userProfile = testRealm().users().userProfile();
        UPConfig upConfigOld = userProfile.getConfiguration();
        UPConfig upConfig = userProfile.getConfiguration();
        upConfig.addOrReplaceAttribute((new UPAttribute(UserModel.EMAIL, new UPAttributePermissions(Set.of(ROLE_USER, ROLE_ADMIN), Set.of(ROLE_ADMIN)))));
        getCleanup().addCleanup(() -> {
            userProfile.update(upConfigOld);
        });
        userProfile.update(upConfig);

        configureRequiredActionsToUser("test-user@localhost", UserModel.RequiredAction.UPDATE_EMAIL.name());

        UserResource testUser = testRealm().users().get(findUser("test-user@localhost").getId());
        assertEquals(1, testUser.toRepresentation().getRequiredActions().size());

        loginPage.open();

        loginPage.login("test-user@localhost", "password");

        // UPDATE_EMAIL required action is skipped and cleared
        appPage.assertCurrent();

        assertEquals(0, testUser.toRepresentation().getRequiredActions().size());
    }
}
