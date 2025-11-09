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
package org.iamshield.authorization.common;

import org.iamshield.OAuth2Constants;
import org.iamshield.authorization.attribute.Attributes;
import org.iamshield.authorization.identity.Identity;
import org.iamshield.common.util.MultivaluedHashMap;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserModel;
import org.iamshield.representations.AccessToken;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ClientModelIdentity implements Identity {
    protected final RealmModel realm;
    protected final ClientModel client;
    protected final UserModel serviceAccount;
    protected final AccessToken token;

    public ClientModelIdentity(IAMShieldSession session, ClientModel client) {
        this(session, client, null);
    }

    public ClientModelIdentity(IAMShieldSession session, ClientModel client, AccessToken token) {
        this.realm = session.getContext().getRealm();
        this.client = client;
        this.serviceAccount = session.users().getServiceAccount(client);
        this.token = token;
    }

    @Override
    public String getId() {
        return client.getId();
    }

    @Override
    public Attributes getAttributes() {
        MultivaluedHashMap map = new MultivaluedHashMap<String, String>();
        if (serviceAccount != null) map.addAll(serviceAccount.getAttributes());
        if (token != null) {
            map.add(OAuth2Constants.SCOPE, token.getScope());
        }
        return Attributes.from(map);
    }

    @Override
    public boolean hasRealmRole(String roleName) {
        if (serviceAccount == null) return false;
        RoleModel role = realm.getRole(roleName);
        if (role == null) return false;
        return serviceAccount.hasRole(role);
    }

    @Override
    public boolean hasClientRole(String clientId, String roleName) {
        if (serviceAccount == null) return false;
        ClientModel client = realm.getClientByClientId(clientId);
        RoleModel role = client.getRole(roleName);
        if (role == null) return false;
        return serviceAccount.hasRole(role);
    }

    @Override
    public boolean hasOneClientRole(String clientId, String... roleNames) {
        if (serviceAccount == null) return false;
        ClientModel client = realm.getClientByClientId(clientId);
        for (String roleName : roleNames) {
            RoleModel role = client.getRole(roleName);
            if (role == null) continue;
            if (serviceAccount.hasRole(role)) return true;
        }
        return false;
    }

}
