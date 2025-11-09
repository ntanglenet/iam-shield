/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.models.light;

import org.iamshield.common.Profile;
import org.iamshield.common.Profile.Feature;
import org.iamshield.models.ClientScopeModel;
import org.iamshield.common.util.SecretGenerator;
import org.iamshield.models.GroupModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.SubjectCredentialManager;
import org.iamshield.models.UserConsentModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserModel.RequiredAction;
import org.iamshield.storage.adapter.AbstractInMemoryUserAdapter;
import org.iamshield.util.JsonSerialization;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 *
 * @author hmlnarik
 */
@JsonIncludeProperties({
    "id",
    "createdTimestamp",
    "emailVerified",
    "enabled",
    "roleIds",
    "groupIds",
    "attributes",
    "requiredActions",
    "federationLink",
    "consents",
    "serviceAccountClientLink",
    "readonly"
})
@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class LightweightUserAdapter extends AbstractInMemoryUserAdapter {

    private Consumer<LightweightUserAdapter> updateHandler = a -> {};

    public static final String ID_PREFIX = "lightweight-";

    private final Set<LightweightConsentEntity> consents = new HashSet<>();

    public static boolean isLightweightUser(UserModel user) {
        return Profile.isFeatureEnabled(Feature.TRANSIENT_USERS) && user instanceof LightweightUserAdapter;
    }

    public static boolean isLightweightUser(String id) {
        return Profile.isFeatureEnabled(Feature.TRANSIENT_USERS) && id != null && id.startsWith(ID_PREFIX);
    }

    public static String getLightweightUserId(String id) {
        return id == null || id.length() < ID_PREFIX.length()
          ? null
          : id.substring(ID_PREFIX.length());
    }

    public LightweightUserAdapter(IAMShieldSession session, String id) {
        super(session, null, ID_PREFIX + (id == null ? SecretGenerator.getInstance().randomString(16) : id));
    }

    public LightweightUserAdapter(IAMShieldSession session, RealmModel realm, String id) {
        super(session, realm, ID_PREFIX + (id == null ? SecretGenerator.getInstance().randomString(16) : id));
    }


    public void setOwningUserSessionId(String id) {
        this.id = ID_PREFIX + (id == null ? UUID.randomUUID().toString() : id);
        update();
    }

    protected LightweightUserAdapter() {
    }

    public static LightweightUserAdapter fromString(IAMShieldSession session, RealmModel realm, String serializedForm) {
        if (serializedForm == null) {
            return null;
        }
        try {
            LightweightUserAdapter res = JsonSerialization.readValue(serializedForm, LightweightUserAdapter.class);
            res.session = session;
            res.realm = realm;
            return res;
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return EmptyCredentialManager.INSTANCE;
    }

    public String serialize() {
        try {
            return JsonSerialization.writeValueAsString(this);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        super.deleteRoleMapping(role);
        update();
    }

    @Override
    public void grantRole(RoleModel role) {
        super.grantRole(role);
        update();
    }

    @Override
    public void setServiceAccountClientLink(String clientInternalId) {
        super.setServiceAccountClientLink(clientInternalId);
        update();
    }

    @Override
    public void setFederationLink(String link) {
        super.setFederationLink(link);
        update();
    }

    @Override
    public void leaveGroup(GroupModel group) {
        super.leaveGroup(group);
        update();
    }

    @Override
    public void joinGroup(GroupModel group) {
        super.joinGroup(group);
        update();
    }

    @Override
    public void setEmailVerified(boolean verified) {
        super.setEmailVerified(verified);
        update();
    }

    @Override
    public void removeRequiredAction(RequiredAction action) {
        super.removeRequiredAction(action);
        update();
    }

    @Override
    public void addRequiredAction(RequiredAction action) {
        super.addRequiredAction(action);
        update();
    }

    @Override
    public void removeRequiredAction(String action) {
        super.removeRequiredAction(action);
        update();
    }

    @Override
    public void addRequiredAction(String action) {
        super.addRequiredAction(action);
        update();
    }

    @Override
    public void removeAttribute(String name) {
        super.removeAttribute(name);
        update();
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        super.setAttribute(name, values);
        update();
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        super.setSingleAttribute(name, value);
        update();
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        update();
    }

    @Override
    public void setCreatedTimestamp(Long timestamp) {
        super.setCreatedTimestamp(timestamp);
        update();
    }

    @Override
    public void setReadonly(boolean flag) {
        super.setReadonly(flag);
        update();
    }

    @Override
    public void addDefaults() {
        super.addDefaults();
        update();
    }

    @Override
    public void setUsername(String username) {
        super.setUsername(username);
        update();
    }

    public void setUpdateHandler(Consumer<LightweightUserAdapter> updateHandler) {
        this.updateHandler = updateHandler == null ? lua -> {} : updateHandler;
    }

    private void update() {
        updateHandler.accept(this);
    }

    public void addConsent(UserConsentModel consent) {
        if (consent != null) {
            consents.add(LightweightConsentEntity.fromModel(consent));
            update();
        }
    }

    public UserConsentModel getConsentByClient(String clientInternalId) {
        return LightweightConsentEntity.toModel(realm, getConsentEntityByClient(clientInternalId));
    }

    public boolean revokeConsentForClient(String clientInternalId) {
        if (clientInternalId != null) {
            final boolean res = consents.removeIf(lce -> clientInternalId.equals(lce.getClientId()));
            if (res) {
                update();
            }
            return res;
        }
        return false;
    }

    public void updateConsent(UserConsentModel consent) {
        if (consent == null) {
            return;
        }

        String clientId = consent.getClient() == null
          ? null
          : consent.getClient().getId();
        LightweightConsentEntity userConsentEntity = getConsentEntityByClient(clientId);

        userConsentEntity.setGrantedClientScopesIds(
                consent.getGrantedClientScopes().stream()
                        .map(ClientScopeModel::getId)
                        .collect(Collectors.toSet())
        );
        update();
    }

    LightweightConsentEntity getConsentEntityByClient(String clientId) {
        return consents.stream().filter(lce -> Objects.equals(clientId, lce.getClientId()))
          .findFirst()
          .orElse(null);
    }

    public Stream<UserConsentModel> getConsentsStream() {
        return consents.stream()
          .map(lce -> LightweightConsentEntity.toModel(realm, lce));
    }


}
