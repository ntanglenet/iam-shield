/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.testsuite.authz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.iamshield.admin.client.resource.AuthorizationResource;
import org.iamshield.authorization.client.AuthzClient;
import org.iamshield.representations.AccessToken;
import org.iamshield.representations.idm.authorization.AuthorizationRequest;
import org.iamshield.representations.idm.authorization.AuthorizationResponse;
import org.iamshield.representations.idm.authorization.JSPolicyRepresentation;
import org.iamshield.representations.idm.authorization.Permission;
import org.iamshield.representations.idm.authorization.PermissionRequest;
import org.iamshield.representations.idm.authorization.PermissionResponse;
import org.iamshield.representations.idm.authorization.ResourceRepresentation;
import org.iamshield.representations.idm.authorization.ScopePermissionRepresentation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UmaPermissionTicketPushedClaimsTest extends AbstractResourceServerTest {

    @Test
    public void testEvaluatePermissionsWithPushedClaims() throws Exception {
        ResourceRepresentation resource = addResource("Bank Account", "withdraw");
        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName("Withdraw Limit Policy");
        policy.setType("script-scripts/withdraw-limit-policy.js");

        AuthorizationResource authorization = getClient(getRealm()).authorization();

        authorization.policies().js().create(policy).close();

        ScopePermissionRepresentation representation = new ScopePermissionRepresentation();

        representation.setName("Withdraw Permission");
        representation.addScope("withdraw");
        representation.addPolicy(policy.getName());

        authorization.permissions().scope().create(representation).close();

        AuthzClient authzClient = getAuthzClient();
        PermissionRequest permissionRequest = new PermissionRequest(resource.getId());

        permissionRequest.addScope("withdraw");
        permissionRequest.setClaim("my.bank.account.withdraw.value", "50.5");

        PermissionResponse response = authzClient.protection("marta", "password").permission().create(permissionRequest);
        AuthorizationRequest request = new AuthorizationRequest();

        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationResponse authorizationResponse = authzClient.authorization().authorize(request);

        assertNotNull(authorizationResponse);
        assertNotNull(authorizationResponse.getToken());

        AccessToken token = toAccessToken(authorizationResponse.getToken());
        Collection<Permission> permissions = token.getAuthorization().getPermissions();

        assertEquals(1, permissions.size());

        Permission permission = permissions.iterator().next();
        Map<String, Set<String>> claims = permission.getClaims();

        assertNotNull(claims);

        assertThat(claims.get("my.bank.account.withdraw.value"), Matchers.containsInAnyOrder("50.5"));

        permissionRequest.setClaim("my.bank.account.withdraw.value", "100.5");

        response = authzClient.protection("marta", "password").permission().create(permissionRequest);
        request = new AuthorizationRequest();

        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        try {
            authorizationResponse = authzClient.authorization().authorize(request);
            fail("Access should be denied");
        } catch (Exception ignore) {

        }
    }
}
