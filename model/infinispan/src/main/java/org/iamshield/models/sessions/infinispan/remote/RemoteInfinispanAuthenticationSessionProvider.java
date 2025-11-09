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

package org.iamshield.models.sessions.infinispan.remote;

import java.util.Map;
import java.util.Objects;

import org.iamshield.cluster.ClusterProvider;
import org.iamshield.common.util.Time;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.cache.infinispan.events.AuthenticationSessionAuthNoteUpdateEvent;
import org.iamshield.models.sessions.infinispan.InfinispanAuthenticationSessionProviderFactory;
import org.iamshield.models.sessions.infinispan.entities.RootAuthenticationSessionEntity;
import org.iamshield.models.sessions.infinispan.remote.transaction.AuthenticationSessionChangeLogTransaction;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.sessions.AuthenticationSessionCompoundId;
import org.iamshield.sessions.AuthenticationSessionProvider;
import org.iamshield.sessions.RootAuthenticationSessionModel;

public class RemoteInfinispanAuthenticationSessionProvider implements AuthenticationSessionProvider {

    private final IAMShieldSession session;
    private final AuthenticationSessionChangeLogTransaction transaction;
    private final int authSessionsLimit;

    public RemoteInfinispanAuthenticationSessionProvider(IAMShieldSession session, int authSessionsLimit, AuthenticationSessionChangeLogTransaction transaction) {
        this.session = Objects.requireNonNull(session);
        this.authSessionsLimit = authSessionsLimit;
        this.transaction = Objects.requireNonNull(transaction);
    }

    @Override
    public void close() {

    }

    @Override
    public RootAuthenticationSessionModel createRootAuthenticationSession(RealmModel realm) {
        return createRootAuthenticationSession(realm, IAMShieldModelUtils.generateId());
    }

    @Override
    public RootAuthenticationSessionModel createRootAuthenticationSession(RealmModel realm, String id) {
        RootAuthenticationSessionEntity entity = new RootAuthenticationSessionEntity(id);
        entity.setRealmId(realm.getId());
        entity.setTimestamp(Time.currentTime());
        var updater = transaction.create(id, entity);
        updater.initialize(session, realm, authSessionsLimit);
        return updater;
    }

    @Override
    public RootAuthenticationSessionModel getRootAuthenticationSession(RealmModel realm, String authenticationSessionId) {
        var updater = transaction.get(authenticationSessionId);
        if(updater != null) {
            updater.initialize(session, realm, authSessionsLimit);
        }
        return updater;
    }

    @Override
    public void removeRootAuthenticationSession(RealmModel realm, RootAuthenticationSessionModel authenticationSession) {
        transaction.remove(authenticationSession.getId());
    }

    @Override
    public void removeAllExpired() {
        // Rely on expiration of cache entries provided by infinispan. Nothing needed here.
    }

    @Override
    public void removeExpired(RealmModel realm) {
        // Rely on expiration of cache entries provided by infinispan. Nothing needed here.
    }

    @Override
    public void onRealmRemoved(RealmModel realm) {
        transaction.removeByRealmId(realm.getId());
    }

    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {
        // No update anything on clientRemove for now. AuthenticationSessions of removed client will be handled at runtime if needed.
    }

    @Override
    public void updateNonlocalSessionAuthNotes(AuthenticationSessionCompoundId compoundId, Map<String, String> authNotesFragment) {
        if (compoundId == null) {
            return;
        }

        session.getProvider(ClusterProvider.class).notify(
                InfinispanAuthenticationSessionProviderFactory.AUTHENTICATION_SESSION_EVENTS,
                AuthenticationSessionAuthNoteUpdateEvent.create(compoundId.getRootSessionId(), compoundId.getTabId(), authNotesFragment),
                true,
                ClusterProvider.DCNotify.ALL_BUT_LOCAL_DC
        );
    }
}
