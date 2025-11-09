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
package org.iamshield.testsuite.model.clientscope;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.ClientScopeModel;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RealmProvider;
import org.iamshield.storage.StorageId;
import org.iamshield.storage.clientscope.ClientScopeStorageProvider;
import org.iamshield.storage.clientscope.ClientScopeStorageProviderModel;
import org.iamshield.testsuite.federation.HardcodedClientScopeStorageProviderFactory;
import org.iamshield.testsuite.model.IAMShieldModelTest;
import org.iamshield.testsuite.model.RequireProvider;

@RequireProvider(RealmProvider.class)
@RequireProvider(ClientScopeStorageProvider.class)
public class ClientScopeStorageTest extends IAMShieldModelTest {

    private String realmId;
    private String clientScopeFederationId;

    @Override
    public void createEnvironment(IAMShieldSession s) {
        RealmModel realm = createRealm(s, "realm");
        s.getContext().setRealm(realm);
        realm.setDefaultRole(s.roles().addRealmRole(realm, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realm.getName()));
        this.realmId = realm.getId();
    }

    @Override
    public void cleanEnvironment(IAMShieldSession s) {
        RealmModel realm = s.realms().getRealm(realmId);
        s.getContext().setRealm(realm);
        s.realms().removeRealm(realmId);
    }

    @Test
    public void testGetClientScopeById() {
        getParameters(ClientScopeStorageProviderModel.class).forEach(fs -> inComittedTransaction(fs, (session, federatedStorage) -> {
            Assume.assumeThat("Cannot handle more than 1 client scope federation provider", clientScopeFederationId, Matchers.nullValue());
            RealmModel realm = session.realms().getRealm(realmId);
            federatedStorage.setParentId(realmId);
            federatedStorage.setEnabled(true);
            federatedStorage.getConfig().putSingle(HardcodedClientScopeStorageProviderFactory.SCOPE_NAME, HardcodedClientScopeStorageProviderFactory.SCOPE_NAME);
            ComponentModel res = realm.addComponentModel(federatedStorage);
            clientScopeFederationId = res.getId();
            log.infof("Added %s client scope federation provider: %s", federatedStorage.getName(), clientScopeFederationId);
            return null;
        }));

        inComittedTransaction(1, (session, i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            StorageId storageId = new StorageId(clientScopeFederationId, "scope_name");
            ClientScopeModel hardcoded = session.clientScopes().getClientScopeById(realm, storageId.getId());
            Assert.assertNotNull(hardcoded);
            return null;
        });
    }
}
