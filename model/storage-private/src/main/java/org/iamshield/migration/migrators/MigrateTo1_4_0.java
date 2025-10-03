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

package org.iamshield.migration.migrators;

import org.iamshield.component.ComponentModel;
import org.iamshield.migration.ModelVersion;
import org.iamshield.models.ImpersonationConstants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.LDAPConstants;
import org.iamshield.models.StorageProviderRealmModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.cache.UserCache;
import org.iamshield.models.utils.DefaultAuthenticationFlows;
import org.iamshield.models.utils.DefaultRequiredActions;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.storage.UserStoragePrivateUtil;
import org.iamshield.storage.UserStorageUtil;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class MigrateTo1_4_0 implements Migration {
    public static final ModelVersion VERSION = new ModelVersion("1.4.0");
    public ModelVersion getVersion() {
        return VERSION;
    }

    public void migrate(IAMShieldSession session) {
        session.realms().getRealmsStream().forEach(realm -> migrateRealm(session, realm));
    }

    protected void migrateRealm(IAMShieldSession session, RealmModel realm) {
        if (realm.getAuthenticationFlowsStream().count() == 0) {
            DefaultAuthenticationFlows.migrateFlows(realm);
            DefaultRequiredActions.addActions(realm);
        }
        ImpersonationConstants.setupImpersonationService(session, realm);

        migrateLDAPMappers(session, realm);
        migrateUsers(session, realm);
    }

    @Override
    public void migrateImport(IAMShieldSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        migrateRealm(session, realm);

    }

    private void migrateLDAPMappers(IAMShieldSession session, RealmModel realm) {
        List<String> mandatoryInLdap = Arrays.asList("username", "username-cn", "first name", "last name");
        ((StorageProviderRealmModel) realm).getUserStorageProvidersStream()
                .filter(providerModel -> Objects.equals(providerModel.getProviderId(), LDAPConstants.LDAP_PROVIDER))
                .forEachOrdered(providerModel -> realm.getComponentsStream(providerModel.getId())
                        .filter(mapper -> mandatoryInLdap.contains(mapper.getName()))
                        .forEach(mapper -> {
                            mapper = new ComponentModel(mapper);  // don't want to modify cache
                            mapper.getConfig().putSingle("is.mandatory.in.ldap", "true");
                            realm.updateComponent(mapper);
                        }));
    }

    private void migrateUsers(IAMShieldSession session, RealmModel realm) {
        Map<String, String> searchAttributes = new HashMap<>(1);
        searchAttributes.put(UserModel.INCLUDE_SERVICE_ACCOUNT, Boolean.FALSE.toString());

        UserStoragePrivateUtil.userLocalStorage(session).searchForUserStream(realm, searchAttributes)
                .forEach(user -> {
                    String email = IAMShieldModelUtils.toLowerCaseSafe(user.getEmail());
                    if (email != null && !email.equals(user.getEmail())) {
                        user.setEmail(email);
                        UserCache userCache = UserStorageUtil.userCache(session);
                        if (userCache != null) {
                            userCache.evict(realm, user);
                        }
                    }
                });
    }
}
