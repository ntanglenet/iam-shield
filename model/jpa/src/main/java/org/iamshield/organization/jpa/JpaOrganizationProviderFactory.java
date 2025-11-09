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

package org.iamshield.organization.jpa;

import org.iamshield.Config.Scope;
import org.iamshield.models.GroupModel;
import org.iamshield.models.GroupModel.GroupEvent;
import org.iamshield.models.ModelValidationException;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.organization.OrganizationProvider;
import org.iamshield.organization.OrganizationProviderFactory;
import org.iamshield.organization.utils.Organizations;
import org.iamshield.provider.ProviderEvent;

public class JpaOrganizationProviderFactory implements OrganizationProviderFactory {

    public static final String ID = "jpa";

    @Override
    public OrganizationProvider create(IAMShieldSession session) {
        return new JpaOrganizationProvider(session);
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        factory.register(this::handleEvents);
    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }

    private void handleEvents(ProviderEvent e) {
        if (e instanceof GroupEvent event) {
            IAMShieldSession session = event.getIAMShieldSession();
            GroupModel group = event.getGroup();
            if (!Organizations.canManageOrganizationGroup(session, group)) {
                throw new ModelValidationException("Can not update organization group");
            }
        }
    }
}
