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

package org.iamshield.models.cache.infinispan.entities;

import org.iamshield.common.util.MultivaluedHashMap;
import org.iamshield.credential.CredentialModel;
import org.iamshield.models.GroupModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.cache.infinispan.DefaultLazyLoader;
import org.iamshield.models.cache.infinispan.LazyLoader;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CachedUser extends AbstractExtendableRevisioned implements InRealm  {

    private final String realm;
    private final Long createdTimestamp;
    private final boolean emailVerified;
    private final boolean enabled;
    private final String federationLink;
    private final String serviceAccountClientLink;
    private final int notBefore;
    private final LazyLoader<UserModel, Set<String>> requiredActions;
    private final LazyLoader<UserModel, MultivaluedHashMap<String, String>> lazyLoadedAttributes;
    private final MultivaluedHashMap<String,String> eagerLoadedAttributes;
    private final LazyLoader<UserModel, Set<String>> roleMappings;
    private final LazyLoader<UserModel, Set<String>> groups;
    private final LazyLoader<UserModel, List<CredentialModel>> storedCredentials;

    public CachedUser(Long revision, RealmModel realm, UserModel user, int notBefore) {
        super(revision, user.getId());
        this.realm = realm.getId();
        this.createdTimestamp = user.getCreatedTimestamp();
        this.emailVerified = user.isEmailVerified();
        this.enabled = user.isEnabled();
        this.federationLink = user.getFederationLink();
        this.serviceAccountClientLink = user.getServiceAccountClientLink();
        this.notBefore = notBefore;
        this.eagerLoadedAttributes = new MultivaluedHashMap<>();
        this.eagerLoadedAttributes.putSingle(UserModel.USERNAME,user.getUsername());
        this.eagerLoadedAttributes.putSingle(UserModel.FIRST_NAME,user.getFirstName());
        this.eagerLoadedAttributes.putSingle(UserModel.LAST_NAME,user.getLastName());
        this.eagerLoadedAttributes.putSingle(UserModel.EMAIL,user.getEmail());
        this.lazyLoadedAttributes = new DefaultLazyLoader<>(userModel -> new MultivaluedHashMap<>(userModel.getAttributes()), MultivaluedHashMap::new);
        this.requiredActions = new DefaultLazyLoader<>(userModel -> userModel.getRequiredActionsStream().collect(Collectors.toSet()), Collections::emptySet);
        this.roleMappings = new DefaultLazyLoader<>(userModel -> userModel.getRoleMappingsStream().map(RoleModel::getId).collect(Collectors.toSet()), Collections::emptySet);
        this.groups = new DefaultLazyLoader<>(userModel -> userModel.getGroupsStream().map(GroupModel::getId).collect(Collectors.toCollection(LinkedHashSet::new)), LinkedHashSet::new);
        this.storedCredentials = new DefaultLazyLoader<>(userModel -> userModel.credentialManager().getStoredCredentialsStream().collect(Collectors.toCollection(LinkedList::new)), LinkedList::new);
    }

    public String getRealm() {
        return realm;
    }

    public String getUsername() {
        return eagerLoadedAttributes.getFirst(UserModel.USERNAME);
    }

    public String getFirstAttribute(IAMShieldSession session, String name, Supplier<UserModel> userModel) {
        if(eagerLoadedAttributes.containsKey(name))
            return eagerLoadedAttributes.getFirst(name);
        else
            return this.lazyLoadedAttributes.get(session, userModel).getFirst(name);
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public String getEmail() {
        return eagerLoadedAttributes.getFirst(UserModel.EMAIL);
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public MultivaluedHashMap<String, String> getAttributes(IAMShieldSession session, Supplier<UserModel> userModel) {
        return lazyLoadedAttributes.get(session, userModel);
    }

    public Set<String> getRequiredActions(IAMShieldSession session, Supplier<UserModel> userModel) {
        return this.requiredActions.get(session, userModel);
    }

    public Set<String> getRoleMappings(IAMShieldSession session, Supplier<UserModel> userModel) {
        return roleMappings.get(session, userModel);
    }

    public String getFederationLink() {
        return federationLink;
    }

    public String getServiceAccountClientLink() {
        return serviceAccountClientLink;
    }

    public Set<String> getGroups(IAMShieldSession session, Supplier<UserModel> userModel) {
        return groups.get(session, userModel);
    }

    public int getNotBefore() {
        return notBefore;
    }

    public List<CredentialModel> getStoredCredentials(IAMShieldSession session, Supplier<UserModel> userModel) {
        // clone the credential model before returning it, so that modifications don't pollute the cache
        return storedCredentials.get(session, userModel).stream().map(CredentialModel::shallowClone).collect(Collectors.toList());
    }

}
