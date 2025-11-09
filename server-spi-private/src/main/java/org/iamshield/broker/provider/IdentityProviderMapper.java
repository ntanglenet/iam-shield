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

package org.iamshield.broker.provider;

import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderSyncMode;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.provider.ConfiguredProvider;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface IdentityProviderMapper extends Provider, ProviderFactory<IdentityProviderMapper>,ConfiguredProvider {
    String ANY_PROVIDER = "*";
    Set<IdentityProviderSyncMode> DEFAULT_IDENTITY_PROVIDER_MAPPER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.LEGACY, IdentityProviderSyncMode.IMPORT));

    String[] getCompatibleProviders();
    String getDisplayCategory();
    String getDisplayType();

    default boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return DEFAULT_IDENTITY_PROVIDER_MAPPER_SYNC_MODES.contains(syncMode);
    }

    /**
     * Called to determine what keycloak username and email to use to process the login request from the external IDP.
     * It's called before "FirstBrokerLogin" flow, so can be used to map attributes to BrokeredIdentityContext ( BrokeredIdentityContext.setUserAttribute ),
     * which will be available on "Review Profile" page and in authenticators during FirstBrokerLogin flow
     *
     *
     * @param session
     * @param realm
     * @param mapperModel
     * @param context
     */
    void preprocessFederatedIdentity(IAMShieldSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context);

    /**
     * Called after UserModel is created for first time for this user. Called after "FirstBrokerLogin" flow
     *
     * @param session
     * @param realm
     * @param user
     * @param mapperModel
     * @param context
     */
    void importNewUser(IAMShieldSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context);

    /**
     * Called when this user has logged in before and has already been imported. Legacy behaviour. When updating the mapper to correctly update brokered users
     * in all sync modes, move the old behavior into this method.
     *
     * @param session
     * @param realm
     * @param user
     * @param mapperModel
     * @param context
     */
    void updateBrokeredUserLegacy(IAMShieldSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context);

    /**
     * Called when this user has logged in before and has already been imported.
     *
     * @param session
     * @param realm
     * @param user
     * @param mapperModel
     * @param context
     */
    void updateBrokeredUser(IAMShieldSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context);
}
