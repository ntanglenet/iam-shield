/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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

import org.eclipse.microprofile.openapi.annotations.Operation;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.iamshield.http.HttpRequest;
import org.iamshield.http.HttpResponse;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.representations.idm.ClientProfilesRepresentation;
import org.iamshield.services.ErrorResponse;
import org.iamshield.services.clientpolicy.ClientPolicyException;
import org.iamshield.services.resources.IAMShieldOpenAPI;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;

@Extension(name = IAMShieldOpenAPI.Profiles.ADMIN, value = "")
public class ClientProfilesResource {
    protected static final Logger logger = Logger.getLogger(ClientProfilesResource.class);

    protected final HttpRequest request;

    protected final HttpResponse response;

    protected final IAMShieldSession session;

    protected final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public ClientProfilesResource(IAMShieldSession session, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.auth = auth;
        this.request = session.getContext().getHttpRequest();
        this.response = session.getContext().getHttpResponse();
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = IAMShieldOpenAPI.Admin.Tags.REALMS_ADMIN)
    @Operation()
    public ClientProfilesRepresentation getProfiles(@QueryParam("include-global-profiles") boolean includeGlobalProfiles) {
        auth.realm().requireViewRealm();

        try {
            return session.clientPolicy().getClientProfiles(realm, includeGlobalProfiles);
        } catch (ClientPolicyException e) {
            throw ErrorResponse.error(e.getError(), Response.Status.BAD_REQUEST);
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = IAMShieldOpenAPI.Admin.Tags.REALMS_ADMIN)
    @Operation()
    public Response updateProfiles(final ClientProfilesRepresentation clientProfiles) {
        auth.realm().requireManageRealm();

        try {
            session.clientPolicy().updateClientProfiles(realm, clientProfiles);
        } catch (ClientPolicyException e) {
            throw ErrorResponse.error(e.getError(), Response.Status.BAD_REQUEST);
        }
        return Response.noContent().build();
    }
}
