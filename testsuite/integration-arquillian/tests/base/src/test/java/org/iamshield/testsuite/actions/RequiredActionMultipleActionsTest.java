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
package org.iamshield.testsuite.actions;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.iamshield.events.Details;
import org.iamshield.events.EventType;
import org.iamshield.models.UserModel.RequiredAction;
import org.iamshield.models.credential.PasswordCredentialModel;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.AssertEvents;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.pages.AppPage.RequestType;
import org.iamshield.testsuite.pages.LoginPage;
import org.iamshield.testsuite.pages.LoginPasswordUpdatePage;
import org.iamshield.testsuite.pages.LoginUpdateProfileEditUsernameAllowedPage;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RequiredActionMultipleActionsTest extends AbstractTestRealmIAMShieldTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        ActionUtil.addRequiredActionForUser(testRealm, "test-user@localhost", RequiredAction.UPDATE_PROFILE.name());
        ActionUtil.addRequiredActionForUser(testRealm, "test-user@localhost", RequiredAction.UPDATE_PASSWORD.name());
    }

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Page
    protected AppPage appPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected LoginPasswordUpdatePage changePasswordPage;

    @Page
    protected LoginUpdateProfileEditUsernameAllowedPage updateProfilePage;

    @Test
    public void updateProfileAndPassword() throws Exception {
        loginPage.open();
        loginPage.login("test-user@localhost", "password");

        String codeId = null;
        if (changePasswordPage.isCurrent()) {
            codeId = updatePassword(codeId);

            updateProfilePage.assertCurrent();
            updateProfile(codeId);
        } else if (updateProfilePage.isCurrent()) {
            codeId = updateProfile(codeId);

            changePasswordPage.assertCurrent();
            updatePassword(codeId);
        } else {
            Assert.fail("Expected to update password and profile before login");
        }

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        events.expectLogin().session(codeId).assertEvent();
    }

    public String updatePassword(String codeId) {
        changePasswordPage.changePassword("new-password", "new-password");

        AssertEvents.ExpectedEvent expectedEvent1 = events.expectRequiredAction(EventType.UPDATE_PASSWORD).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE);
        if (codeId != null) {
            expectedEvent1.detail(Details.CODE_ID, codeId);
        }
        EventRepresentation eventRep1 = expectedEvent1.assertEvent();

        AssertEvents.ExpectedEvent expectedEvent2 = events.expectRequiredAction(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.TYPE);
        if (codeId != null) {
            expectedEvent2.detail(Details.CODE_ID, codeId);
        }
        EventRepresentation eventRep2 = expectedEvent2.assertEvent();

        Assert.assertEquals(eventRep1.getDetails().get(Details.CODE_ID), eventRep2.getDetails().get(Details.CODE_ID));
        return eventRep2.getDetails().get(Details.CODE_ID);
    }

    public String updateProfile(String codeId) {
        updateProfilePage.prepareUpdate().username("test-user@localhost").firstName("New first").lastName("New last")
                .email("new@email.com").submit();

        AssertEvents.ExpectedEvent expectedEvent = events.expectRequiredAction(EventType.UPDATE_PROFILE)
                .detail(Details.UPDATED_FIRST_NAME, "New first")
                .detail(Details.UPDATED_LAST_NAME, "New last")
                .detail(Details.PREVIOUS_EMAIL, "test-user@localhost")
                .detail(Details.UPDATED_EMAIL, "new@email.com");

        if (codeId != null) {
            expectedEvent.detail(Details.CODE_ID, codeId);
        }
        return expectedEvent.assertEvent().getDetails().get(Details.CODE_ID);
    }

}
