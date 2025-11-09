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

package org.iamshield.testsuite.federation.ldap;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runners.MethodSorters;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.storage.ldap.LDAPStorageProvider;
import org.iamshield.storage.ldap.mappers.HardcodedAttributeMapper;
import org.iamshield.storage.ldap.mappers.HardcodedAttributeMapperFactory;
import org.iamshield.storage.ldap.mappers.LDAPStorageMapper;
import org.iamshield.testsuite.runonserver.RunOnServerException;
import org.iamshield.testsuite.util.LDAPRule;
import org.iamshield.testsuite.util.LDAPTestUtils;


@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LDAPHardcodedAttributeTest extends AbstractLDAPTest {

   @ClassRule
   public static LDAPRule ldapRule = new LDAPRule();

   @Rule
   public ExpectedException exceptionRule = ExpectedException.none();

   @Override
   protected LDAPRule getLDAPRule() {
      return ldapRule;
   }

   @Override
   protected void afterImportTestRealm() {
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         ComponentModel localeMapperModel = IAMShieldModelUtils.createComponentModel("localeMapper", ctx.getLdapModel().getId(), HardcodedAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                HardcodedAttributeMapper.USER_MODEL_ATTRIBUTE, "locale",
                HardcodedAttributeMapper.ATTRIBUTE_VALUE, "en");
         ComponentModel emailVerifiedMapperModel = IAMShieldModelUtils.createComponentModel("emailVerifiedMapper", ctx.getLdapModel().getId(), HardcodedAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                HardcodedAttributeMapper.USER_MODEL_ATTRIBUTE, "emailVerified",
                HardcodedAttributeMapper.ATTRIBUTE_VALUE, "true");

         appRealm.addComponentModel(localeMapperModel);
         appRealm.addComponentModel(emailVerifiedMapperModel);

          // Delete all LDAP users and add some new for testing
         LDAPStorageProvider ldapFedProvider = LDAPTestUtils.getLdapProvider(session, ctx.getLdapModel());
         LDAPTestUtils.removeAllLDAPUsers(ldapFedProvider, appRealm);

         LDAPTestUtils.addLDAPUser(ldapFedProvider, appRealm, "johnkeycloak", "John", "Doe",
               "john@email.org", null, "1234");

      });
   }


   @Test
   public void testHarcodedMapper(){
      testingClient.server().run(session -> {
            LDAPTestContext ctx = LDAPTestContext.init(session);
            RealmModel appRealm = ctx.getRealm();

            UserModel user = session.users().getUserByUsername(appRealm, "johnkeycloak");
            Assert.assertNotNull(user);
            Assert.assertTrue(user.isEmailVerified());
            Assert.assertEquals("en", user.getFirstAttribute("locale"));
        });
   }

   @Test
   public void testConfigInvalid(){
      exceptionRule.expect(RunOnServerException.class);
      exceptionRule.expectMessage("Attribute Name cannot be set to username or email");
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         ComponentModel usernameMapperModel = IAMShieldModelUtils.createComponentModel("usernameMapper", ctx.getLdapModel().getId(), HardcodedAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                HardcodedAttributeMapper.USER_MODEL_ATTRIBUTE, "username",
                HardcodedAttributeMapper.ATTRIBUTE_VALUE, "username");
         appRealm.addComponentModel(usernameMapperModel);
      });
   }
}