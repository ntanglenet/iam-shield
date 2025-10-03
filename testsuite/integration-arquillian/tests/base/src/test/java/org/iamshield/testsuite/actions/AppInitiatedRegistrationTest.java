package org.iamshield.testsuite.actions;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.locale.LocaleSelectorProvider;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.Assert;
import org.iamshield.testsuite.admin.ApiUtil;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.pages.RegisterPage;

public class AppInitiatedRegistrationTest extends AbstractTestRealmIAMShieldTest {

    @Page
    protected AppPage appPage;

    @Page
    protected RegisterPage registerPage;

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    @Before
    public void before() {
        ApiUtil.removeUserByUsername(testRealm(), "test-user@localhost");
    }

    @Test
    public void ensureLocaleParameterIsPropagatedDuringAppInitiatedRegistration() {

        oauth.registrationForm()
                .param(LocaleSelectorProvider.KC_LOCALE_PARAM, "en")
                .open();

        registerPage.assertCurrent();
        registerPage.register("first", "last", "test-user@localhost", "test-user", "test","test");

        appPage.assertCurrent();

        UserRepresentation user = testRealm().users().searchByEmail("test-user@localhost", true).get(0);
        // ensure that the locale was set on the user
        Assert.assertEquals("en", user.getAttributes().get("locale").get(0));
    }
}
