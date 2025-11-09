/*
 *  Copyright 2016 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.iamshield.authorization.policy.provider.role;

import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.attribute.Attributes.Entry;
import org.iamshield.authorization.identity.Identity;
import org.iamshield.authorization.identity.UserModelIdentity;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.authorization.policy.evaluation.Evaluation;
import org.iamshield.authorization.fgap.evaluation.partial.PartialEvaluationPolicyProvider;
import org.iamshield.authorization.policy.provider.PolicyProvider;
import org.iamshield.authorization.store.PolicyStore;
import org.iamshield.authorization.store.StoreFactory;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserProvider;
import org.iamshield.representations.JsonWebToken;
import org.iamshield.representations.idm.authorization.ResourceType;
import org.iamshield.representations.idm.authorization.RolePolicyRepresentation;

import static org.iamshield.models.utils.RoleUtils.getDeepUserRoleMappings;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RolePolicyProvider implements PolicyProvider, PartialEvaluationPolicyProvider {

    private final BiFunction<Policy, AuthorizationProvider, RolePolicyRepresentation> representationFunction;

    private static final Logger logger = Logger.getLogger(RolePolicyProvider.class);

    public RolePolicyProvider(BiFunction<Policy, AuthorizationProvider, RolePolicyRepresentation> representationFunction) {
        this.representationFunction = representationFunction;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        Policy policy = evaluation.getPolicy();
        RolePolicyRepresentation policyRep = representationFunction.apply(policy, evaluation.getAuthorizationProvider());
        AuthorizationProvider authorizationProvider = evaluation.getAuthorizationProvider();
        RealmModel realm = authorizationProvider.getIAMShieldSession().getContext().getRealm();
        Identity identity = evaluation.getContext().getIdentity();

        if (isGranted(realm, authorizationProvider, policyRep, identity)) {
            evaluation.grant();
        }

        logger.debugf("policy %s evaluated with status %s on identity %s", policy.getName(), evaluation.getEffect(), identity.getId());
    }

    private boolean isGranted(RealmModel realm, AuthorizationProvider authorizationProvider, RolePolicyRepresentation policyRep, Identity identity) {
        Set<RolePolicyRepresentation.RoleDefinition> roleIds = policyRep.getRoles();
        boolean granted = false;

        for (RolePolicyRepresentation.RoleDefinition roleDefinition : roleIds) {
            RoleModel role = realm.getRoleById(roleDefinition.getId());

            if (role != null) {
                boolean isFetchRoles = policyRep.isFetchRoles() != null && policyRep.isFetchRoles();
                boolean hasRole = hasRole(identity, role, realm, authorizationProvider, isFetchRoles);

                if (!hasRole && roleDefinition.isRequired() != null && roleDefinition.isRequired()) {
                    return false;
                } else if (hasRole) {
                    granted = true;
                }
            }
        }

        return granted;
    }

    private boolean hasRole(Identity identity, RoleModel role, RealmModel realm, AuthorizationProvider authorizationProvider, boolean fetchRoles) {
        if (fetchRoles) {
            UserModel subject = getSubject(identity, realm, authorizationProvider);
            return subject != null && subject.hasRole(role);
        }
        String roleName = role.getName();
        if (role.isClientRole()) {
            ClientModel clientModel = realm.getClientById(role.getContainerId());
            return identity.hasClientRole(clientModel.getClientId(), roleName);
        }
        return identity.hasRealmRole(roleName);
    }

    private UserModel getSubject(Identity identity, RealmModel realm, AuthorizationProvider authorizationProvider) {
        IAMShieldSession session = authorizationProvider.getIAMShieldSession();
        UserProvider users = session.users();
        UserModel user = users.getUserById(realm, identity.getId());

        if (user == null) {
            Entry sub = identity.getAttributes().getValue(JsonWebToken.SUBJECT);

            if (sub == null || sub.isEmpty()) {
                return null;
            }

            return users.getUserById(realm, sub.asString(0));
        }

        return user;
    }

    @Override
    public void close() {

    }

    @Override
    public Stream<Policy> getPermissions(IAMShieldSession session, ResourceType resourceType, UserModel subject) {
        AuthorizationProvider provider = session.getProvider(AuthorizationProvider.class);
        RealmModel realm = session.getContext().getRealm();
        ClientModel adminPermissionsClient = realm.getAdminPermissionsClient();
        StoreFactory storeFactory = provider.getStoreFactory();
        ResourceServer resourceServer = storeFactory.getResourceServerStore().findByClient(adminPermissionsClient);
        PolicyStore policyStore = storeFactory.getPolicyStore();
        List<String> roleIds = getDeepUserRoleMappings(subject).stream().map(RoleModel::getId).toList();
        Stream<Policy> policies = Stream.of();

        return Stream.concat(policies, policyStore.findDependentPolicies(resourceServer, resourceType.getType(), RolePolicyProviderFactory.ID, "roles", roleIds));
    }

    @Override
    public boolean evaluate(IAMShieldSession session, Policy policy, UserModel adminUser) {
        RealmModel realm = session.getContext().getRealm();
        AuthorizationProvider authorizationProvider = session.getProvider(AuthorizationProvider.class);
        return isGranted(realm, authorizationProvider, representationFunction.apply(policy, authorizationProvider), new UserModelIdentity(realm, adminUser));
    }

    @Override
    public boolean supports(Policy policy) {
        return RolePolicyProviderFactory.ID.equals(policy.getType());
    }
}
