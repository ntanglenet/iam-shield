/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.testsuite.model;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.iamshield.broker.provider.IdentityProvider;
import org.iamshield.broker.provider.IdentityProviderFactory;
import org.iamshield.models.Constants;
import org.iamshield.models.FederatedIdentityModel;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.provider.ProviderEventListener;
import org.iamshield.testsuite.broker.oidc.TestKeycloakOidcIdentityProviderFactory;

/**
 * @author Réda Housni Alaoui
 */
@RequireProvider(value = IdentityProvider.class, only = TestKeycloakOidcIdentityProviderFactory.ID)
public class FederatedIdentityModelTest extends IAMShieldModelTest {

	private static final String IDENTITY_PROVIDER_ALIAS = "idp-test";
	private static final String USERNAME = "jdoe";
	private String realmId;
	private String userId;

	@Override
	public void createEnvironment(IAMShieldSession s) {
		RealmModel realm = createRealm(s, "realm");
        s.getContext().setRealm(realm);
		realm.setDefaultRole(s.roles().addRealmRole(realm, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realm.getName()));

		this.realmId = realm.getId();

		IdentityProviderFactory identityProviderFactory = (IdentityProviderFactory) s.getIAMShieldSessionFactory()
				.getProviderFactory(IdentityProvider.class, TestKeycloakOidcIdentityProviderFactory.ID);

		IdentityProviderModel identityProviderModel = identityProviderFactory.createConfig();
		identityProviderModel.setAlias(IDENTITY_PROVIDER_ALIAS);
        s.identityProviders().create(identityProviderModel);

		userId = s.users().addUser(realm, USERNAME).getId();
	}

	@Override
	public void cleanEnvironment(IAMShieldSession s) {
        RealmModel realm = s.realms().getRealm(realmId);
        s.getContext().setRealm(realm);
		s.realms().removeRealm(realmId);
	}

	@Test
	public void addFederatedIdentity() {

		List<FederatedIdentityModel.FederatedIdentityCreatedEvent> recordedEvents = new ArrayList<>();
		ProviderEventListener providerEventListener = event -> {
			if (event instanceof FederatedIdentityModel.FederatedIdentityCreatedEvent) {
				recordedEvents.add((FederatedIdentityModel.FederatedIdentityCreatedEvent) event);
			}
		};
		getFactory().register(providerEventListener);
		try {
			withRealm(realmId, (session, realm) -> {
				FederatedIdentityModel federatedIdentity = new FederatedIdentityModel(IDENTITY_PROVIDER_ALIAS, userId, USERNAME);
				UserModel user = session.users().getUserById(realm, userId);
				session.users().addFederatedIdentity(realm, user, federatedIdentity);

				assertThat(recordedEvents, hasSize(1));
				FederatedIdentityModel.FederatedIdentityCreatedEvent event = recordedEvents.get(0);
				assertThat(event.getIAMShieldSession(), equalTo(session));
				assertThat(event.getRealm(), equalTo(realm));
				assertThat(event.getUser(), equalTo(user));
				assertThat(event.getFederatedIdentity(), equalTo(federatedIdentity));

				return null;
			});
		} finally {
			getFactory().unregister(providerEventListener);
		}
	}

	@Test
	public void removeFederatedIdentity() {
		List<FederatedIdentityModel.FederatedIdentityRemovedEvent> recordedEvents = new ArrayList<>();
		ProviderEventListener providerEventListener = event -> {
			if (event instanceof FederatedIdentityModel.FederatedIdentityRemovedEvent) {
				recordedEvents.add((FederatedIdentityModel.FederatedIdentityRemovedEvent) event);
			}
		};
		getFactory().register(providerEventListener);
		try {
			withRealm(realmId, (session, realm) -> {
				FederatedIdentityModel federatedIdentity = new FederatedIdentityModel(IDENTITY_PROVIDER_ALIAS, userId, USERNAME);
				UserModel user = session.users().getUserById(realm, userId);
				session.users().addFederatedIdentity(realm, user, federatedIdentity);

				session.users().removeFederatedIdentity(realm, user, IDENTITY_PROVIDER_ALIAS);

				assertThat(recordedEvents, hasSize(1));
				FederatedIdentityModel.FederatedIdentityRemovedEvent event = recordedEvents.get(0);
				assertThat(event.getIAMShieldSession(), equalTo(session));
				assertThat(event.getRealm(), equalTo(realm));
				assertThat(event.getUser(), equalTo(user));
				assertThat(event.getFederatedIdentity(), equalTo(federatedIdentity));

				return null;
			});
		} finally {
			getFactory().unregister(providerEventListener);
		}
	}

}
