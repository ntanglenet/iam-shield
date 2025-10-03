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
package org.iamshield.tests.admin;

import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.ClientsResource;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.common.Profile;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.authorization.DecisionStrategy;
import org.iamshield.representations.idm.authorization.Logic;
import org.iamshield.representations.idm.authorization.ResourceServerRepresentation;
import org.iamshield.representations.idm.authorization.RolePolicyRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.RealmConfig;
import org.iamshield.testframework.realm.RealmConfigBuilder;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.util.JsonSerialization;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@IAMShieldIntegrationTest(config = AuthzCleanupTest.AuthzCleanupServerConfig.class)
public class AuthzCleanupTest {

    @InjectRealm(config = AuthzCleanupRealmConfig.class)
    ManagedRealm managedRealm;

    @InjectRunOnServer(permittedPackages = "org.iamshield.tests")
    RunOnServerClient runOnServer;

    private static final String clientId = "myclient";
    private static final String clientSecret = "secret";
    private static final String realmName = "default";

    @Test
    public void testCreate() throws Exception {
        ClientsResource clients = managedRealm.admin().clients();
        ClientRepresentation client = clients.findByClientId(clientId).get(0);
        ResourceServerRepresentation settings = JsonSerialization.readValue(AuthzCleanupTest.class.getResourceAsStream("authz/acme-resource-server-cleanup-test.json"), ResourceServerRepresentation.class);

        clients.get(client.getId()).authorization().importSettings(settings);

        runOnServer.run(AuthzCleanupTest::setup);
    }

    public static void setup(IAMShieldSession session) {
        RealmModel realm = session.realms().getRealmByName(realmName);
        session.getContext().setRealm(realm);
        AuthorizationProvider authz = session.getProvider(AuthorizationProvider.class);
        ClientModel myClient = realm.getClientByClientId(clientId);
        ResourceServer resourceServer = authz.getStoreFactory().getResourceServerStore().findByClient(myClient);
        createRolePolicy(authz, resourceServer, myClient.getClientId() + "/client-role-1");
        createRolePolicy(authz, resourceServer, myClient.getClientId() + "/client-role-2");
    }

    private static Policy createRolePolicy(AuthorizationProvider authz, ResourceServer resourceServer, String roleName) {
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName(roleName);
        representation.setType("role");
        representation.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        representation.setLogic(Logic.POSITIVE);
        representation.addRole(roleName, true);

        return authz.getStoreFactory().getPolicyStore().create(resourceServer, representation);
    }

    public static class AuthzCleanupServerConfig implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder builder) {
            builder.features(Profile.Feature.AUTHORIZATION);

            return builder;
        }
    }

    private static class AuthzCleanupRealmConfig implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            realm.addClient(clientId).secret(clientSecret).authorizationServicesEnabled(true).redirectUris("http://localhost/myclient");
            realm.roles("client-role-1",
                    "client-role-2",
                    "Acme administrator",
                    "Acme viewer",
                    "tenant administrator",
                    "tenant viewer",
                    "tenant user");

            return realm;
        }
    }
}
