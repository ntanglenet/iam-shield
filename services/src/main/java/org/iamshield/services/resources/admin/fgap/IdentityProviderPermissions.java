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
package org.iamshield.services.resources.admin.fgap;

import org.jboss.logging.Logger;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.common.ClientModelIdentity;
import org.iamshield.authorization.common.DefaultEvaluationContext;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.model.Resource;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.authorization.model.Scope;
import org.iamshield.authorization.policy.evaluation.EvaluationContext;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.iamshield.services.resources.admin.fgap.AdminPermissionManagement.TOKEN_EXCHANGE;

/**
 * Manages default policies for identity providers.
 *
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
class IdentityProviderPermissions implements  IdentityProviderPermissionManagement {
    private static final Logger logger = Logger.getLogger(IdentityProviderPermissions.class);
    protected final IAMShieldSession session;
    protected final RealmModel realm;
    protected final AuthorizationProvider authz;
    protected final MgmtPermissions root;

    public IdentityProviderPermissions(IAMShieldSession session, RealmModel realm, AuthorizationProvider authz, MgmtPermissions root) {
        this.session = session;
        this.realm = realm;
        this.authz = authz;
        this.root = root;
    }

    private String getResourceName(IdentityProviderModel idp) {
        return "idp.resource." + idp.getInternalId();
    }

    private String getExchangeToPermissionName(IdentityProviderModel idp) {
        return TOKEN_EXCHANGE + ".permission.idp." + idp.getInternalId();
    }

    private void initialize(IdentityProviderModel idp) {
        ResourceServer server = root.initializeRealmResourceServer();
        if (server == null) return;
        Scope exchangeToScope = root.initializeScope(TOKEN_EXCHANGE, server);

        String resourceName = getResourceName(idp);
        Resource resource = authz.getStoreFactory().getResourceStore().findByName(server, resourceName);
        if (resource == null) {
            resource = authz.getStoreFactory().getResourceStore().create(server, resourceName, server.getClientId());
            resource.setType("IdentityProvider");
            Set<Scope> scopeset = new HashSet<>();
            scopeset.add(exchangeToScope);
            resource.updateScopes(scopeset);
        }
        String exchangeToPermissionName = getExchangeToPermissionName(idp);
        Policy exchangeToPermission = authz.getStoreFactory().getPolicyStore().findByName(server, exchangeToPermissionName);
        if (exchangeToPermission == null) {
            Helper.addEmptyScopePermission(authz, server, exchangeToPermissionName, resource, exchangeToScope);
        }
    }

    private void deletePolicy(String name, ResourceServer server) {
        Policy policy = authz.getStoreFactory().getPolicyStore().findByName(server, name);
        if (policy != null) {
            authz.getStoreFactory().getPolicyStore().delete(policy.getId());
        }

    }

    private void deletePermissions(IdentityProviderModel idp) {
        ResourceServer server = root.initializeRealmResourceServer();
        if (server == null) return;
        deletePolicy(getExchangeToPermissionName(idp), server);
        Resource resource = authz.getStoreFactory().getResourceStore().findByName(server, getResourceName(idp));;
        if (resource != null) authz.getStoreFactory().getResourceStore().delete(resource.getId());
    }

    @Override
    public boolean isPermissionsEnabled(IdentityProviderModel idp) {
        ResourceServer server = root.initializeRealmResourceServer();
        if (server == null) return false;

        return authz.getStoreFactory().getResourceStore().findByName(server, getResourceName(idp)) != null;
    }

    @Override
    public void setPermissionsEnabled(IdentityProviderModel idp, boolean enable) {
        if (enable) {
            initialize(idp);
        } else {
            deletePermissions(idp);
        }
    }



    private Scope exchangeToScope(ResourceServer server) {
        return authz.getStoreFactory().getScopeStore().findByName(server, TOKEN_EXCHANGE);
    }

    @Override
    public Resource resource(IdentityProviderModel idp) {
        ResourceServer server = root.initializeRealmResourceServer();
        if (server == null) return null;
        Resource resource =  authz.getStoreFactory().getResourceStore().findByName(server, getResourceName(idp));
        if (resource == null) return null;
        return resource;
    }


    @Override
    public Map<String, String> getPermissions(IdentityProviderModel idp) {
        if (authz==null) return null;
        initialize(idp);
        Map<String, String> scopes = new LinkedHashMap<>();
        scopes.put(TOKEN_EXCHANGE, exchangeToPermission(idp).getId());
        return scopes;
    }

    @Override
    public boolean canExchangeTo(ClientModel authorizedClient, IdentityProviderModel to) {
        ResourceServer server = root.initializeRealmResourceServer();
        if (server == null) {
            logger.debug("No resource server set up for target idp");
            return false;
        }

        Resource resource =  authz.getStoreFactory().getResourceStore().findByName(server, getResourceName(to));
        if (resource == null) {
            logger.debug("No resource object set up for target idp");
            return false;
        }

        Policy policy = authz.getStoreFactory().getPolicyStore().findByName(server, getExchangeToPermissionName(to));
        if (policy == null) {
            logger.debug("No permission object set up for target idp");
            return false;
        }

        Set<Policy> associatedPolicies = policy.getAssociatedPolicies();
        // if no policies attached to permission then just do default behavior
        if (associatedPolicies == null || associatedPolicies.isEmpty()) {
            logger.debug("No policies set up for permission on target idp");
            return false;
        }

        Scope scope = exchangeToScope(server);
        if (scope == null) {
            logger.debug(TOKEN_EXCHANGE + " not initialized");
            return false;
        }
        ClientModelIdentity identity = new ClientModelIdentity(session, authorizedClient);
        EvaluationContext context = new DefaultEvaluationContext(identity, session) {
            @Override
            public Map<String, Collection<String>> getBaseAttributes() {
                Map<String, Collection<String>> attributes = super.getBaseAttributes();
                attributes.put("kc.client.id", Arrays.asList(authorizedClient.getClientId()));
                return attributes;
            }

        };
        return root.evaluatePermission(resource, server, context, scope);
    }

    @Override
    public Policy exchangeToPermission(IdentityProviderModel idp) {
        ResourceServer server = root.initializeRealmResourceServer();
        if (server == null) return null;
        return authz.getStoreFactory().getPolicyStore().findByName(server, getExchangeToPermissionName(idp));
    }

}
