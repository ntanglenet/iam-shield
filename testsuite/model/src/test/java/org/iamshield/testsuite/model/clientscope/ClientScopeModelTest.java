/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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
import org.iamshield.models.ClientModel;
import org.iamshield.models.ClientProvider;
import org.iamshield.models.ClientScopeModel;
import org.iamshield.models.ClientScopeProvider;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RealmProvider;
import org.iamshield.models.RoleProvider;
import org.iamshield.models.cache.CacheRealmProvider;
import org.iamshield.testsuite.model.IAMShieldModelTest;
import org.iamshield.testsuite.model.RequireProvider;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

/**
 *
 * @author hmlnarik
 */
@RequireProvider(RealmProvider.class)
@RequireProvider(ClientProvider.class)
@RequireProvider(ClientScopeProvider.class)
@RequireProvider(RoleProvider.class)
public class ClientScopeModelTest extends IAMShieldModelTest {

    private String realmId;

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
    public void testClientScopes() {
        List<String> clientScopes = new LinkedList<>();
        withRealm(realmId, (session, realm) -> {
            ClientModel client = session.clients().addClient(realm, "myClientId");

            ClientScopeModel clientScope1 = session.clientScopes().addClientScope(realm, "myClientScope1");
            clientScopes.add(clientScope1.getId());
            ClientScopeModel clientScope2 = session.clientScopes().addClientScope(realm, "myClientScope2");
            clientScopes.add(clientScope2.getId());


            client.addClientScope(clientScope1, true);
            client.addClientScope(clientScope2, false);

            return null;
        });

        withRealm(realmId, (session, realm) -> {
            List<String> actualClientScopes = session.clientScopes().getClientScopesStream(realm).map(ClientScopeModel::getId).collect(Collectors.toList());
            assertThat(actualClientScopes, containsInAnyOrder(clientScopes.toArray()));

            ClientScopeModel clientScopeById = session.clientScopes().getClientScopeById(realm, clientScopes.get(0));
            assertThat(clientScopeById.getId(), is(clientScopes.get(0)));

            session.clientScopes().removeClientScopes(realm);

            return null;
        });

        withRealm(realmId, (session, realm) -> {
            List<ClientScopeModel> actualClientScopes = session.clientScopes().getClientScopesStream(realm).collect(Collectors.toList());
            assertThat(actualClientScopes, empty());

            return null;
        });
    }

    @Test
    @RequireProvider(value=ClientScopeProvider.class, only="jpa")
    @RequireProvider(value=CacheRealmProvider.class)
    public void testClientScopesCaching() {
        List<String> clientScopes = new LinkedList<>();
        withRealm(realmId, (session, realm) -> {
            ClientScopeModel clientScope = session.clientScopes().addClientScope(realm, "myClientScopeForCaching");
            clientScopes.add(clientScope.getId());

            assertionsForClientScopesCaching(clientScopes, session, realm);
            return null;
        });

        withRealm(realmId, (session, realm) -> {
            assertionsForClientScopesCaching(clientScopes, session, realm);
            return null;
        });

    }

    private static void assertionsForClientScopesCaching(List<String> clientScopes, IAMShieldSession session, RealmModel realm) {
        assertThat(clientScopes, Matchers.containsInAnyOrder(realm.getClientScopesStream()
                .map(ClientScopeModel::getId).toArray(String[]::new)));

        assertThat(clientScopes, Matchers.containsInAnyOrder(session.clientScopes().getClientScopesStream(realm)
                .map(ClientScopeModel::getId).toArray(String[]::new)));
    }

}
