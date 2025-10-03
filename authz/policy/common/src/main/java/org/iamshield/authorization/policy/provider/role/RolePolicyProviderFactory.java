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

package org.iamshield.authorization.policy.provider.role;

import org.iamshield.Config;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.model.Policy;
import org.iamshield.authorization.policy.provider.PolicyProvider;
import org.iamshield.authorization.policy.provider.PolicyProviderFactory;
import org.iamshield.authorization.policy.provider.util.PolicyValidationException;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.representations.idm.authorization.PolicyRepresentation;
import org.iamshield.representations.idm.authorization.RolePolicyRepresentation;
import org.iamshield.representations.idm.authorization.RolePolicyRepresentation.RoleDefinition;
import org.iamshield.util.JsonSerialization;
import org.iamshield.utils.StringUtil;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RolePolicyProviderFactory implements PolicyProviderFactory<RolePolicyRepresentation> {

    public static final String ID = "role";
    private RolePolicyProvider provider = new RolePolicyProvider(this::toRepresentation);

    @Override
    public String getName() {
        return "Role";
    }

    @Override
    public String getGroup() {
        return "Identity Based";
    }

    @Override
    public PolicyProvider create(AuthorizationProvider authorization) {
        return provider;
    }

    @Override
    public PolicyProvider create(IAMShieldSession session) {
        return provider;
    }

    @Override
    public RolePolicyRepresentation toRepresentation(Policy policy, AuthorizationProvider authorization) {
        RolePolicyRepresentation representation = new RolePolicyRepresentation();
        String roles = policy.getConfig().get("roles");

        representation.setRoles(getRoles(roles, authorization.getRealm()));

        String fetchRoles = policy.getConfig().get("fetchRoles");

        if (StringUtil.isNotBlank(fetchRoles)) {
            representation.setFetchRoles(Boolean.parseBoolean(fetchRoles));
        }

        return representation;
    }

    @Override
    public Class<RolePolicyRepresentation> getRepresentationType() {
        return RolePolicyRepresentation.class;
    }

    @Override
    public void onCreate(Policy policy, RolePolicyRepresentation representation, AuthorizationProvider authorization) {
        updateRoles(policy, representation, authorization);
    }

    @Override
    public void onUpdate(Policy policy, RolePolicyRepresentation representation, AuthorizationProvider authorization) {
        updateRoles(policy, representation, authorization);
    }

    @Override
    public void onImport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        updateRoles(policy, authorization, getRoles(representation.getConfig().get("roles"), authorization.getRealm()));
        String fetchRoles = representation.getConfig().get("fetchRoles");

        if (StringUtil.isNotBlank(fetchRoles)) {
            policy.putConfig("fetchRoles", fetchRoles);
        }
    }

    @Override
    public void onExport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorizationProvider) {
        Map<String, String> config = new HashMap<>();
        Set<RolePolicyRepresentation.RoleDefinition> roles = toRepresentation(policy, authorizationProvider).getRoles();

        for (RolePolicyRepresentation.RoleDefinition roleDefinition : roles) {
            RoleModel role = authorizationProvider.getRealm().getRoleById(roleDefinition.getId());

            if (role.isClientRole()) {
                roleDefinition.setId(ClientModel.class.cast(role.getContainer()).getClientId() + "/" + role.getName());
            } else {
                roleDefinition.setId(role.getName());
            }
        }

        try {
            config.put("roles", JsonSerialization.writeValueAsString(roles));
        } catch (IOException cause) {
            throw new RuntimeException("Failed to export role policy [" + policy.getName() + "]", cause);
        }

        String fetchRoles = policy.getConfig().get("fetchRoles");

        if (StringUtil.isNotBlank(fetchRoles)) {
            config.put("fetchRoles", fetchRoles);
        }

        representation.setConfig(config);
    }

    private void updateRoles(Policy policy, RolePolicyRepresentation representation, AuthorizationProvider authorization) {
        if (representation.isFetchRoles() != null) {
            policy.putConfig("fetchRoles", String.valueOf(representation.isFetchRoles()));
        }
        updateRoles(policy, authorization, representation.getRoles());
    }

    private void updateRoles(Policy policy, AuthorizationProvider authorization, Set<RolePolicyRepresentation.RoleDefinition> roles) {
        Set<RolePolicyRepresentation.RoleDefinition> updatedRoles = new HashSet<>();
        Set<String> processedRoles = new HashSet<>();
        if (roles != null) {
            RealmModel realm = authorization.getRealm();
            for (RolePolicyRepresentation.RoleDefinition definition : roles) {
                RoleModel role = getRole(definition, realm);
                if (role == null) {
                    continue;
                }

                if (!processedRoles.add(role.getId())) {
                    throw new PolicyValidationException("Role can't be specified multiple times - " + role.getName());
                }
                definition.setId(role.getId());
                updatedRoles.add(definition);
            }
        }

        try {
            policy.putConfig("roles", JsonSerialization.writeValueAsString(updatedRoles));
        } catch (IOException cause) {
            throw new RuntimeException("Failed to serialize roles", cause);
        }
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }

    private Set<RoleDefinition> getRoles(String rawRoles, RealmModel realm) {
        if (rawRoles != null) {
            try {
                return Arrays.stream(JsonSerialization.readValue(rawRoles, RoleDefinition[].class))
                        .filter(definition -> getRole(definition, realm) != null)
                        .sorted()
                        .collect(Collectors.toCollection(LinkedHashSet::new));
            } catch (IOException e) {
                throw new RuntimeException("Could not parse roles from config: [" + rawRoles + "]", e);
            }
        }

        return Collections.emptySet();
    }

    public static final Pattern UUID_PATTERN = Pattern.compile("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}");

    private RoleModel getRole(RolePolicyRepresentation.RoleDefinition definition, RealmModel realm) {
        String roleName = definition.getId();
        String clientId = null;
        int clientIdSeparator = roleName.indexOf("/");

        if (clientIdSeparator != -1) {
            clientId = roleName.substring(0, clientIdSeparator);
            roleName = roleName.substring(clientIdSeparator + 1);
        }

        RoleModel role;

        if (clientId == null) {
            // if the role name looks like a UUID, it is likely that it is a role ID. Then do this look-up first to avoid hitting the database twice
            // TODO: In a future version of the auth feature, make this more strict to avoid the double lookup and any ambiguity
            boolean looksLikeAUuid = UUID_PATTERN.matcher(roleName).matches();
            role = looksLikeAUuid ? realm.getRoleById(roleName) : realm.getRole(roleName);

            if (role == null) {
                role = !looksLikeAUuid ? realm.getRoleById(roleName) : realm.getRole(roleName);;
            }
        } else {
            ClientModel client = realm.getClientByClientId(clientId);

            if (client == null) {
                throw new RuntimeException("Client with id [" + clientId + "] not found.");
            }

            role = client.getRole(roleName);
        }

        return role;
    }
}
