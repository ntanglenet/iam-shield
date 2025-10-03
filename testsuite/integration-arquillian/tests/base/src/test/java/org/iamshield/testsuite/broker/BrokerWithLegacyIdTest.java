/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.broker;

import org.junit.Test;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.representations.idm.FederatedIdentityRepresentation;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.broker.oidc.LegacyIdIdentityProviderFactory;
import org.iamshield.testsuite.util.AccountHelper;
import org.iamshield.testsuite.util.FederatedIdentityBuilder;
import org.iamshield.testsuite.util.UserBuilder;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.iamshield.testsuite.admin.ApiUtil.createUserWithAdminClient;
import static org.iamshield.testsuite.broker.BrokerTestConstants.IDP_OIDC_ALIAS;
import static org.iamshield.testsuite.broker.oidc.LegacyIdIdentityProvider.LEGACY_ID;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public class BrokerWithLegacyIdTest extends AbstractInitializedBaseBrokerTest {
    private static final UserRepresentation consumerUser = UserBuilder.create()
                                                                            .username("anakin")
                                                                            .firstName("Darth")
                                                                            .lastName("Vader")
                                                                            .email("anakin@skywalker.tatooine")
                                                                            .password("Come to the Dark Side. We have cookies")
                                                                            .build();
    private UserResource consumerUserResource;

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration() {
            @Override
            public IdentityProviderRepresentation setUpIdentityProvider(IdentityProviderSyncMode syncMode) {
                IdentityProviderRepresentation idp = super.setUpIdentityProvider(syncMode);
                idp.setProviderId(LegacyIdIdentityProviderFactory.PROVIDER_ID);
                return idp;
            }
        };
    }

    @Override
    public void beforeBrokerTest() {
        super.beforeBrokerTest();
        RealmResource consumerRealm = realmsResouce().realm(bc.consumerRealmName());

        String consumerUserId = createUserWithAdminClient(consumerRealm, consumerUser);

        FederatedIdentityRepresentation identity = FederatedIdentityBuilder.create()
                .userId(LEGACY_ID)
                .userName(bc.getUserLogin())
                .identityProvider(IDP_OIDC_ALIAS)
                .build();

        consumerUserResource = consumerRealm.users().get(consumerUserId);
        consumerUserResource.addFederatedIdentity(IDP_OIDC_ALIAS, identity);
    }

    @Test
    public void loginWithLegacyId() {
        assertEquals(LEGACY_ID, getFederatedIdentity().getUserId());
        // login as existing user with legacy ID (from e.g. a deprecated API)
        logInAsUserInIDP();
        // id should be migrated to new one
        assertEquals(userId, getFederatedIdentity().getUserId());
        appPage.assertCurrent();

        AccountHelper.logout(adminClient.realm(bc.providerRealmName()), bc.getUserLogin());

        // try to login again to double check the new ID works
        logInAsUserInIDP();
        assertEquals(userId, getFederatedIdentity().getUserId());
        appPage.assertCurrent();
    }

    private FederatedIdentityRepresentation getFederatedIdentity() {
        List<FederatedIdentityRepresentation> identities = consumerUserResource.getFederatedIdentity();
        assertEquals(1, identities.size());
        return identities.get(0);
    }
}
