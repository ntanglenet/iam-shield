/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.authorization.admin;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.model.ResourceServer;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.services.resources.IAMShieldOpenAPI;
import org.iamshield.services.resources.admin.AdminEventBuilder;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Extension(name = IAMShieldOpenAPI.Profiles.ADMIN, value = "")
public class AuthorizationService {

    private final AdminPermissionEvaluator auth;
    private final ClientModel client;
    private ResourceServer resourceServer;
    private final AuthorizationProvider authorization;
    private final AdminEventBuilder adminEvent;

    public AuthorizationService(IAMShieldSession session, ClientModel client, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.client = client;
        this.authorization = session.getProvider(AuthorizationProvider.class);
        this.adminEvent = adminEvent;
        this.resourceServer = this.authorization.getStoreFactory().getResourceServerStore().findByClient(this.client);
        this.auth = auth;
    }

    @Path("/resource-server")
    public ResourceServerService resourceServer() {
        if (resourceServer == null) {
            throw new NotFoundException();
        }

        return getResourceServerService();
    }

    public ResourceServerService getResourceServerService() {
        return new ResourceServerService(this.authorization, this.resourceServer, this.client, this.auth, adminEvent);
    }

    public void enable(boolean newClient) {
        this.resourceServer = getResourceServerService().create(newClient);
    }

    public void disable() {
        if (isEnabled()) {
            getResourceServerService().delete();
        }
    }

    public boolean isEnabled() {
        return this.resourceServer != null;
    }
}
