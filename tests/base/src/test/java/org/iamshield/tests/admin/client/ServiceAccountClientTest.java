/*
 * Copyright 2024 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.iamshield.tests.admin.client;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.resource.ClientScopeResource;
import org.iamshield.common.constants.ServiceAccountConstants;
import org.iamshield.representations.AccessToken;
import org.iamshield.representations.idm.ClientScopeRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testframework.annotations.InjectClient;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ClientConfig;
import org.iamshield.testframework.realm.ClientConfigBuilder;
import org.iamshield.testframework.realm.ManagedClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.tests.utils.admin.ApiUtil;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;

import java.util.stream.Collectors;

/**
 * @author rmartinc
 */
@IAMShieldIntegrationTest
public class ServiceAccountClientTest {

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectClient(config = ServiceAccountClientConfig.class)
    ManagedClient managedClient;

    @InjectOAuthClient
    OAuthClient oAuthClient;

    private static final String clientId = "service-account-client";

    @Test
    public void testServiceAccountEnableDisable() {
        ClientScopeResource serviceAccountScopeRsc = ApiUtil.findClientScopeByName(
                managedRealm.admin(), ServiceAccountConstants.SERVICE_ACCOUNT_SCOPE);
        Assertions.assertNotNull(serviceAccountScopeRsc);
        ClientScopeRepresentation serviceAccountScope = serviceAccountScopeRsc.toRepresentation();

        MatcherAssert.assertThat(
                managedClient.admin().getDefaultClientScopes().stream()
                        .map(ClientScopeRepresentation::getName)
                        .collect(Collectors.toList()),
                Matchers.hasItem("service_account")
        );

        // perform a login and check the claims are there
        oAuthClient.client(clientId, "password");
        AccessTokenResponse response = oAuthClient.doClientCredentialsGrantAccessTokenRequest();
        AccessToken accessToken = oAuthClient.verifyToken(response.getAccessToken());
        Assertions.assertEquals(clientId, accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ID));
        Assertions.assertNotNull(accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_HOST));
        Assertions.assertNotNull(accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ADDRESS));

        // update the client to remove service account
        managedClient.updateWithCleanup(c -> c.serviceAccountsEnabled(false));
        MatcherAssert.assertThat(
                managedClient.admin().getDefaultClientScopes().stream()
                        .map(ClientScopeRepresentation::getName)
                        .collect(Collectors.toList()),
                Matchers.not(Matchers.hasItem(ServiceAccountConstants.SERVICE_ACCOUNT_SCOPE))
        );
        response = oAuthClient.doClientCredentialsGrantAccessTokenRequest();
        Assertions.assertEquals("unauthorized_client", response.getError());

        // re-enable sevice accounts
        managedClient.updateWithCleanup(c -> c.serviceAccountsEnabled(true));
        MatcherAssert.assertThat(
                managedClient.admin().getDefaultClientScopes().stream()
                        .map(ClientScopeRepresentation::getName)
                        .collect(Collectors.toList()),
                Matchers.hasItem(ServiceAccountConstants.SERVICE_ACCOUNT_SCOPE)
        );
        response = oAuthClient.doClientCredentialsGrantAccessTokenRequest();
        accessToken = oAuthClient.verifyToken(response.getAccessToken());
        Assertions.assertEquals("service-account-client", accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ID));
        Assertions.assertNotNull(accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_HOST));
        Assertions.assertNotNull(accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ADDRESS));

        // assign the scope as optional
        managedClient.admin().removeDefaultClientScope(serviceAccountScope.getId());
        managedClient.admin().addOptionalClientScope(serviceAccountScope.getId());

        // re-enable service accounts, should assign the scope again as default
        managedClient.updateWithCleanup(c -> c.serviceAccountsEnabled(true));
        MatcherAssert.assertThat(
                managedClient.admin().getDefaultClientScopes().stream()
                        .map(ClientScopeRepresentation::getName)
                        .collect(Collectors.toList()),
                Matchers.hasItem(ServiceAccountConstants.SERVICE_ACCOUNT_SCOPE)
        );
        response = oAuthClient.doClientCredentialsGrantAccessTokenRequest();
        accessToken = oAuthClient.verifyToken(response.getAccessToken());
        Assertions.assertEquals("service-account-client", accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ID));
        Assertions.assertNotNull(accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_HOST));
        Assertions.assertNotNull(accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ADDRESS));

        // remove the service account and client credentials should fail
        UserRepresentation serviceAccountUser = managedClient.admin().getServiceAccountUser();
        managedRealm.admin().users().delete(serviceAccountUser.getId()).close();
        response = oAuthClient.doClientCredentialsGrantAccessTokenRequest();
        Assertions.assertEquals("invalid_request", response.getError());
    }

    private static class ServiceAccountClientConfig implements ClientConfig {

        @Override
        public ClientConfigBuilder configure(ClientConfigBuilder client) {
            return client
                    .clientId(clientId)
                    .protocol("openid-connect")
                    .secret("password")
                    .serviceAccountsEnabled(true)
                    .authenticatorType("client-secret")
                    .publicClient(false);
        }
    }
}
