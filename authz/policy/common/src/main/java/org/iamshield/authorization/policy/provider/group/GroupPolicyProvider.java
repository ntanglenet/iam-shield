/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.authorization.policy.provider.group;

import static org.iamshield.models.utils.ModelToRepresentation.buildGroupPath;

import java.util.List;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.attribute.Attributes;
import org.iamshield.authorization.attribute.Attributes.Entry;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.authorization.policy.evaluation.Evaluation;
import org.iamshield.authorization.fgap.evaluation.partial.PartialEvaluationPolicyProvider;
import org.iamshield.authorization.policy.provider.PolicyProvider;
import org.iamshield.authorization.store.PolicyStore;
import org.iamshield.authorization.store.StoreFactory;
import org.iamshield.models.ClientModel;
import org.iamshield.models.GroupModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.ModelToRepresentation;
import org.iamshield.representations.idm.authorization.GroupPolicyRepresentation;
import org.iamshield.representations.idm.authorization.ResourceType;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class GroupPolicyProvider implements PolicyProvider, PartialEvaluationPolicyProvider {

    private static final Logger logger = Logger.getLogger(GroupPolicyProvider.class);
    private final BiFunction<Policy, AuthorizationProvider, GroupPolicyRepresentation> representationFunction;

    public GroupPolicyProvider(BiFunction<Policy, AuthorizationProvider, GroupPolicyRepresentation> representationFunction) {
        this.representationFunction = representationFunction;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        AuthorizationProvider authorizationProvider = evaluation.getAuthorizationProvider();
        GroupPolicyRepresentation policy = representationFunction.apply(evaluation.getPolicy(), authorizationProvider);
        RealmModel realm = authorizationProvider.getRealm();
        Attributes.Entry groupsClaim = evaluation.getContext().getIdentity().getAttributes().getValue(policy.getGroupsClaim());

        if (groupsClaim == null || groupsClaim.isEmpty()) {
            List<String> userGroups = evaluation.getRealm().getUserGroups(evaluation.getContext().getIdentity().getId());
            groupsClaim = new Entry(policy.getGroupsClaim(), userGroups);
        }

        if (isGranted(realm, policy, groupsClaim)) {
            evaluation.grant();
        }

        logger.debugf("Groups policy %s evaluated to %s with identity groups %s", policy.getName(), evaluation.getEffect(), groupsClaim);
    }

    private boolean isGranted(RealmModel realm, GroupPolicyRepresentation policy, Attributes.Entry groupsClaim) {
        for (GroupPolicyRepresentation.GroupDefinition definition : policy.getGroups()) {
            GroupModel allowedGroup = realm.getGroupById(definition.getId());

            if (allowedGroup == null) {
                continue;
            }

            for (int i = 0; i < groupsClaim.size(); i++) {
                String group = groupsClaim.asString(i);

                if (group.indexOf('/') != -1) {
                    String allowedGroupPath = buildGroupPath(allowedGroup);
                    if (group.equals(allowedGroupPath) || (definition.isExtendChildren() && group.startsWith(allowedGroupPath))) {
                        return true;
                    }
                }

                // in case the group from the claim does not represent a path, we just check an exact name match
                if (group.equals(allowedGroup.getName())) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public Stream<Policy> getPermissions(IAMShieldSession session, ResourceType resourceType, UserModel user) {
        AuthorizationProvider provider = session.getProvider(AuthorizationProvider.class);
        RealmModel realm = session.getContext().getRealm();
        ClientModel adminPermissionsClient = realm.getAdminPermissionsClient();
        StoreFactory storeFactory = provider.getStoreFactory();
        ResourceServer resourceServer = storeFactory.getResourceServerStore().findByClient(adminPermissionsClient);
        PolicyStore policyStore = storeFactory.getPolicyStore();
        List<String> groupIds = user.getGroupsStream().map(GroupModel::getId).toList();

        return policyStore.findDependentPolicies(resourceServer, resourceType.getType(), GroupPolicyProviderFactory.ID, "groups", groupIds);
    }

    @Override
    public boolean evaluate(IAMShieldSession session, Policy policy, UserModel subject) {
        RealmModel realm = session.getContext().getRealm();
        AuthorizationProvider authorizationProvider = session.getProvider(AuthorizationProvider.class);
        GroupPolicyRepresentation groupPolicy = representationFunction.apply(policy, authorizationProvider);
        List<String> userGroups = subject.getGroupsStream().map(ModelToRepresentation::buildGroupPath)
                .collect(Collectors.toList());
        return isGranted(realm, groupPolicy, new Entry(groupPolicy.getGroupsClaim(), userGroups));
    }

    @Override
    public boolean supports(Policy policy) {
        return GroupPolicyProviderFactory.ID.equals(policy.getType());
    }

    @Override
    public void close() {

    }
}
