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

package org.iamshield.organization.admin.resource;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.NoCache;
import org.iamshield.events.admin.OperationType;
import org.iamshield.events.admin.ResourceType;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ModelValidationException;
import org.iamshield.models.OrganizationModel;
import org.iamshield.models.utils.ModelToRepresentation;
import org.iamshield.models.utils.RepresentationToModel;
import org.iamshield.organization.OrganizationProvider;
import org.iamshield.organization.validation.OrganizationsValidation;
import org.iamshield.organization.validation.OrganizationsValidation.OrganizationValidationException;
import org.iamshield.representations.idm.OrganizationRepresentation;
import org.iamshield.services.ErrorResponse;
import org.iamshield.services.resources.IAMShieldOpenAPI;
import org.iamshield.services.resources.admin.AdminEventBuilder;

import java.util.Objects;

@Extension(name = IAMShieldOpenAPI.Profiles.ADMIN, value = "")
public class OrganizationResource {

    private final IAMShieldSession session;
    private final OrganizationProvider provider;
    private final AdminEventBuilder adminEvent;
    private final OrganizationModel organization;

    public OrganizationResource(IAMShieldSession session, OrganizationModel organization, AdminEventBuilder adminEvent) {
        this.session = session;
        this.provider = session == null ? null : session.getProvider(OrganizationProvider.class);
        this.organization = organization;
        this.adminEvent = adminEvent.resource(ResourceType.ORGANIZATION);
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = IAMShieldOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Returns the organization representation")
    @APIResponses(value = {
        @APIResponse(responseCode = "200", description = "", content = @Content(schema = @Schema(implementation = OrganizationRepresentation.class)))
    })
    public OrganizationRepresentation get() {
        return ModelToRepresentation.toRepresentation(organization, false);
    }

    @DELETE
    @Tag(name = IAMShieldOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Deletes the organization")
    @APIResponses(value = {
        @APIResponse(responseCode = "204", description = "No Content"),
        @APIResponse(responseCode = "400", description = "Bad Request")
    })
    public Response delete() {
        boolean removed = provider.remove(organization);
        if (removed) {
            adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri()).success();
            return Response.noContent().build();
        } else {
            throw ErrorResponse.error("organization couldn't be deleted", Status.BAD_REQUEST);
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = IAMShieldOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Updates the organization")
    @APIResponses(value = {
        @APIResponse(responseCode = "204", description = "No Content"),
        @APIResponse(responseCode = "400", description = "Bad Request"),
        @APIResponse(responseCode = "409", description = "Conflict")
    })
    public Response update(OrganizationRepresentation organizationRep) {
        // attempt to change organization name to an existing organization name
        if (!Objects.equals(organization.getName(), organizationRep.getName()) &&
                provider.getAllStream(organizationRep.getName(), true, -1, -1).findAny().isPresent()) {
            throw ErrorResponse.error("A organization with the same name already exists.", Status.CONFLICT);
        }

        try {
            OrganizationsValidation.validateUrl(organizationRep.getRedirectUrl());
            RepresentationToModel.toModel(organizationRep, organization);
            adminEvent.operation(OperationType.UPDATE).resourcePath(session.getContext().getUri()).representation(organizationRep).success();
            return Response.noContent().build();
        } catch (ModelValidationException | OrganizationValidationException ex) {
            throw ErrorResponse.error(ex.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    @Path("members")
    public OrganizationMemberResource members() {
        return new OrganizationMemberResource(session, organization, adminEvent);
    }

    @Path("identity-providers")
    public OrganizationIdentityProvidersResource identityProvider() {
        return new OrganizationIdentityProvidersResource(session, organization, adminEvent);
    }
}
