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

package org.iamshield.storage;

import org.iamshield.models.ClientProvider;
import org.iamshield.models.ClientScopeProvider;
import org.iamshield.models.GroupProvider;
import org.iamshield.models.IdentityProviderStorageProvider;
import org.iamshield.models.RealmProvider;
import org.iamshield.models.RoleProvider;
import org.iamshield.models.SingleUseObjectProvider;
import org.iamshield.models.UserLoginFailureProvider;
import org.iamshield.models.UserProvider;
import org.iamshield.models.UserSessionProvider;
import org.iamshield.provider.Provider;
import org.iamshield.sessions.AuthenticationSessionProvider;


public interface DatastoreProvider extends Provider {
    AuthenticationSessionProvider authSessions();

    ClientScopeProvider clientScopes();

    ClientProvider clients();

    GroupProvider groups();

    IdentityProviderStorageProvider identityProviders();

    UserLoginFailureProvider loginFailures();

    RealmProvider realms();

    RoleProvider roles();

    SingleUseObjectProvider singleUseObjects();

    UserProvider users();

    UserSessionProvider userSessions();

    ExportImportManager getExportImportManager();
}
