/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.model.authz;

import org.junit.Ignore;
import org.junit.Test;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.authorization.store.StoreFactory;
import org.iamshield.models.ClientModel;
import org.iamshield.models.ClientProvider;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RealmProvider;
import org.iamshield.models.UserModel;
import org.iamshield.models.cache.authorization.CachedStoreFactoryProvider;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.models.utils.ModelToRepresentation;
import org.iamshield.representations.idm.authorization.UmaPermissionRepresentation;
import org.iamshield.representations.idm.authorization.UserPolicyRepresentation;
import org.iamshield.testsuite.model.IAMShieldModelTest;
import org.iamshield.testsuite.model.RequireProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

@RequireProvider(CachedStoreFactoryProvider.class)
@RequireProvider(RealmProvider.class)
@RequireProvider(ClientProvider.class)
public class ConcurrentAuthzTest extends IAMShieldModelTest {

    private String realmId;
    private String resourceServerId;
    private String resourceId;
    private String adminId;

    @Override
    protected void createEnvironment(IAMShieldSession s) {
        RealmModel realm = createRealm(s, "test");
        s.getContext().setRealm(realm);
        realm.setDefaultRole(s.roles().addRealmRole(realm, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realm.getName()));

        realmId = realm.getId();

        ClientModel client = s.clients().addClient(realm, "my-server");

        AuthorizationProvider authorization = s.getProvider(AuthorizationProvider.class);
        StoreFactory aStore = authorization.getStoreFactory();

        ResourceServer rs = aStore.getResourceServerStore().create(client);
        resourceServerId = rs.getId();
        resourceId =  aStore.getResourceStore().create(rs, "myResource", client.getClientId()).getId();
        aStore.getScopeStore().create(rs, "read");

        adminId = s.users().addUser(realm, "admin").getId();
    }

    @Override
    protected void cleanEnvironment(IAMShieldSession s) {
        RealmModel realm = s.realms().getRealm(realmId);
        s.getContext().setRealm(realm);
        s.realms().removeRealm(realmId);
    }

    @Override
    protected boolean isUseSameIAMShieldSessionFactoryForAllThreads() {
        return true;
    }

    @Test
    public void testPermissionRemoved() {
        IntStream.range(0, 500).parallel().forEach(index -> {
            String permissionId = withRealm(realmId, (session, realm) -> {
                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
                StoreFactory aStore = authorization.getStoreFactory();
                ResourceServer rs = aStore.getResourceServerStore().findById(resourceServerId);

                UserModel u = session.users().addUser(realm, "user" + index);

                UmaPermissionRepresentation permission = new UmaPermissionRepresentation();
                permission.setName(IAMShieldModelUtils.generateId());
                permission.addUser(u.getUsername());
                permission.addScope("read");

                permission.addResource(resourceId);
                permission.setOwner(adminId);
                return aStore.getPolicyStore().create(rs, permission).getId();
            });

            withRealm(realmId, (session, realm) -> {
                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
                StoreFactory aStore = authorization.getStoreFactory();

                aStore.getPolicyStore().delete(permissionId);
                return null;
            });

            withRealm(realmId, (session, realm) -> {
                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
                StoreFactory aStore = authorization.getStoreFactory();
                ResourceServer rs = aStore.getResourceServerStore().findById(resourceServerId);

                Map<Policy.FilterOption, String[]> searchMap = new HashMap<>();
                searchMap.put(Policy.FilterOption.TYPE, new String[]{"uma"});
                searchMap.put(Policy.FilterOption.OWNER, new String[]{adminId});
                searchMap.put(Policy.FilterOption.PERMISSION, new String[] {"true"});
                Set<String> s = aStore.getPolicyStore().find(rs, searchMap, 0, 500).stream().map(Policy::getId).collect(Collectors.toSet());
                assertThat(s, not(contains(permissionId)));
                return null;
            });
        });
    }

    @Test
    @Ignore // This is ignored due to intermittent failure, see https://github.com/keycloak/keycloak/issues/14917
    public void testStaleCacheConcurrent() {
        String permissionId = withRealm(realmId, (session, realm) -> {
            AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
            StoreFactory aStore = authorization.getStoreFactory();
            UserModel u = session.users().getUserById(realm, adminId);
            ResourceServer rs = aStore.getResourceServerStore().findById(resourceServerId);


            UmaPermissionRepresentation permission = new UmaPermissionRepresentation();
            permission.setName(IAMShieldModelUtils.generateId());
            permission.addUser(u.getUsername());
            permission.addScope("read");

            permission.addResource(resourceId);
            permission.setOwner(adminId);
            return aStore.getPolicyStore().create(rs, permission).getId();
        });

        IntStream.range(0, 500).parallel().forEach(index -> {
            String createdPolicyId = withRealm(realmId, (session, realm) -> {
                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
                StoreFactory aStore = authorization.getStoreFactory();
                ResourceServer rs = aStore.getResourceServerStore().findById(resourceServerId);
                Policy permission = aStore.getPolicyStore().findById(rs, permissionId);

                UserPolicyRepresentation userRep = new UserPolicyRepresentation();
                userRep.setName("isAdminUser" + index);
                userRep.addUser("admin");
                Policy associatedPolicy = aStore.getPolicyStore().create(rs, userRep);
                permission.addAssociatedPolicy(associatedPolicy);
                return associatedPolicy.getId();
            });

            withRealm(realmId, (session, realm) -> {
                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
                StoreFactory aStore = authorization.getStoreFactory();
                ResourceServer rs = aStore.getResourceServerStore().findById(resourceServerId);
                Policy permission = aStore.getPolicyStore().findById(rs, permissionId);

                assertThat(permission.getAssociatedPolicies(), not(contains(nullValue())));
                ModelToRepresentation.toRepresentation(permission, authorization);

                return null;
            });

            withRealm(realmId, (session, realm) -> {
                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
                StoreFactory aStore = authorization.getStoreFactory();
                aStore.getPolicyStore().delete(createdPolicyId);
                return null;
            });
        });
    }
}
