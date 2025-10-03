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

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.services.resources.admin.ext.AdminRealmResourceProvider;
import org.iamshield.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;

public class ClearKeysCacheRealmAdminProvider implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider  {

    @Override
    public AdminRealmResourceProvider create(IAMShieldSession session) {
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
        return "clear-keys-cache";
    }

    @Override
    public Object getResource(IAMShieldSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        return new ClearKeysCacheResource(session, auth, adminEvent);
    }
}
