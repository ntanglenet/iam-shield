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
 *
 */

package org.iamshield.testsuite.federation.ldap;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.LDAPConstants;
import org.iamshield.models.RealmModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.storage.StorageId;
import org.iamshield.storage.UserStorageProviderModel;
import org.iamshield.storage.ldap.LDAPStorageProvider;
import org.iamshield.storage.ldap.idm.model.LDAPObject;
import org.iamshield.storage.ldap.mappers.HardcodedLDAPAttributeMapper;
import org.iamshield.storage.ldap.mappers.HardcodedLDAPAttributeMapperFactory;
import org.iamshield.storage.ldap.mappers.LDAPStorageMapper;
import org.iamshield.testsuite.admin.ApiUtil;
import org.iamshield.testsuite.pages.AppPage;
import org.iamshield.testsuite.util.AccountHelper;
import org.iamshield.testsuite.util.LDAPRule;
import org.iamshield.testsuite.util.LDAPTestConfiguration;
import org.iamshield.testsuite.util.LDAPTestUtils;

/**
 * Test for the LDAPv3 Password modify extension (https://tools.ietf.org/html/rfc3062)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LDAPPasswordModifyExtensionTest extends AbstractLDAPTest  {

    // Run this test for embedded ApacheDS
    @ClassRule
    public static LDAPRule ldapRule = new LDAPRule()
            .assumeTrue((LDAPTestConfiguration ldapConfig) -> {

                return (ldapConfig.isStartEmbeddedLdapServer());

            });

    @Override
    protected LDAPRule getLDAPRule() {
        return ldapRule;
    }

    @Override
    protected void afterImportTestRealm() {
        testingClient.server().run(session -> {
            LDAPTestContext ctx = LDAPTestContext.init(session);
            RealmModel appRealm = ctx.getRealm();

            // Enable Password Modify extension
            UserStorageProviderModel model = ctx.getLdapModel();
            model.put(LDAPConstants.USE_PASSWORD_MODIFY_EXTENDED_OP, true);
            appRealm.updateComponent(model);

            ComponentModel randomLDAPPasswordMapper = IAMShieldModelUtils.createComponentModel("random initial password", model.getId(), HardcodedLDAPAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                    HardcodedLDAPAttributeMapper.LDAP_ATTRIBUTE_NAME, LDAPConstants.USER_PASSWORD_ATTRIBUTE,
                    HardcodedLDAPAttributeMapper.LDAP_ATTRIBUTE_VALUE, HardcodedLDAPAttributeMapper.RANDOM_ATTRIBUTE_VALUE);
            appRealm.addComponentModel(randomLDAPPasswordMapper);
        });

        testingClient.server().run(session -> {
            LDAPTestContext ctx = LDAPTestContext.init(session);
            RealmModel appRealm = ctx.getRealm();
            // Delete all LDAP users and add some new for testing
            LDAPStorageProvider ldapFedProvider = LDAPTestUtils.getLdapProvider(session, ctx.getLdapModel());
            LDAPTestUtils.removeAllLDAPUsers(ldapFedProvider, appRealm);

            LDAPObject john = LDAPTestUtils.addLDAPUser(ldapFedProvider, appRealm, "johnkeycloak", "John", "Doe", "john@email.org", null, "1234");
            LDAPTestUtils.updateLDAPPassword(ldapFedProvider, john, "Password1");

            appRealm.getClientByClientId("test-app").setDirectAccessGrantsEnabled(true);
        });
    }

    @Test
    public void ldapPasswordChangeWithAccountConsole() throws Exception {
        Assert.assertTrue(AccountHelper.updatePassword(testRealm(), "johnkeycloak", "New-password1"));

        loginPage.open();
        loginPage.login("johnkeycloak", "Bad-password1");
        Assert.assertEquals("Invalid username or password.", loginPage.getInputError());

        loginPage.open();
        loginPage.login("johnkeycloak", "New-password1");
        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());

        // Change password back to previous value
        Assert.assertTrue(AccountHelper.updatePassword(testRealm(), "johnkeycloak", "Password1"));
    }

    @Test
    public void registerUserLdapSuccess() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.assertCurrent();

        registerPage.register("firstName", "lastName", "email2@check.cz", "registerUserSuccess2", "Password1", "Password1");
        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());

        UserRepresentation user = ApiUtil.findUserByUsername(testRealm(),"registerUserSuccess2");
        Assert.assertNotNull(user);
        assertFederatedUserLink(user);
        Assert.assertEquals("registerusersuccess2", user.getUsername());
        Assert.assertEquals("firstName", user.getFirstName());
        Assert.assertEquals("lastName", user.getLastName());
        Assert.assertTrue(user.isEnabled());
    }


    protected void assertFederatedUserLink(UserRepresentation user) {
        Assert.assertTrue(StorageId.isLocalStorage(user.getId()));
        Assert.assertNotNull(user.getFederationLink());
        Assert.assertEquals(user.getFederationLink(), ldapModelId);
    }
}
