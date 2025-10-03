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

package org.iamshield.models.session;

import org.iamshield.Config;
import org.iamshield.models.AuthenticatedClientSessionModel;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserSessionModel;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Persistence of userSessions is disabled . Useful just if you never need survive of userSessions/clientSessions
 * among server restart. Offline sessions / offline tokens will be invalid after server restart as well,
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DisabledUserSessionPersisterProvider implements UserSessionPersisterProviderFactory, UserSessionPersisterProvider {

    public static final String ID = "disabled";

    @Override
    public UserSessionPersisterProvider create(IAMShieldSession session) {
        return this;
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

    @Override
    public void createUserSession(UserSessionModel userSession, boolean offline) {

    }

    @Override
    public void createClientSession(AuthenticatedClientSessionModel clientSession, boolean offline) {

    }

    @Override
    public void removeUserSession(String userSessionId, boolean offline) {

    }

    @Override
    public void removeClientSession(String userSessionId, String clientUUID, boolean offline) {

    }

    @Override
    public void onRealmRemoved(RealmModel realm) {

    }

    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {

    }

    @Override
    public void onUserRemoved(RealmModel realm, UserModel user) {

    }

    @Override
    public void updateLastSessionRefreshes(RealmModel realm, int lastSessionRefresh, Collection<String> userSessionIds, boolean offline) {

    }

    @Override
    public void removeExpired(RealmModel realm) {

    }

    public UserSessionModel loadUserSession(RealmModel realm, String userSessionId, boolean offline) {
        return null;
    }

    @Override
    public Stream<UserSessionModel> loadUserSessionsStream(RealmModel realm, ClientModel client, boolean offline, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserSessionModel> loadUserSessionsStream(RealmModel realm, UserModel user, boolean offline, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserSessionModel> loadUserSessionsStream(Integer firstResult, Integer maxResults, boolean offline,
                                                           String lastUserSessionId) {
        return Stream.empty();
    }

    @Override
    public AuthenticatedClientSessionModel loadClientSession(RealmModel realm, ClientModel client, UserSessionModel userSession, boolean offline) {
        return null;
    }

    @Override
    public int getUserSessionsCount(boolean offline) {
        return 0;
    }

    @Override
    public int getUserSessionsCount(RealmModel realm, ClientModel clientModel, boolean offline) {
        return 0;
    }

    @Override
    public Map<String, Long> getUserSessionsCountsByClients(RealmModel realm, boolean offline) {
        return Collections.emptyMap();
    }
}
