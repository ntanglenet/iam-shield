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

package org.iamshield.services.resources.admin;

import org.iamshield.events.admin.OperationType;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.cache.CachePublicKeyProvider;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.Context;

public class ClearKeysCacheResource {

    protected final AdminPermissionEvaluator auth;
    protected final RealmModel realm;
    private final AdminEventBuilder adminEvent;

    protected final IAMShieldSession session;

    public ClearKeysCacheResource(IAMShieldSession session, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.session = session;
        this.auth = auth;
        this.realm = session.getContext().getRealm();
        this.adminEvent = adminEvent;
    }

    /**
     * Clear cache of external public keys (Public keys of clients or Identity providers)
     *
     */
    @POST
    public void clearKeysCache() {
        auth.realm().requireManageRealm();

        CachePublicKeyProvider cache = session.getProvider(CachePublicKeyProvider.class);
        if (cache != null) {
            cache.clearCache();
        }

        adminEvent.operation(OperationType.ACTION).resourcePath(session.getContext().getUri()).success();
    }
}
