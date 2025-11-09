package org.iamshield.admin.ui.rest;

import java.util.stream.Stream;

import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.jboss.resteasy.reactive.NoCache;
import org.iamshield.admin.ui.rest.model.RealmNameRepresentation;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.services.resources.admin.fgap.AdminPermissions;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.iamshield.services.resources.admin.fgap.RealmsPermissionEvaluator;

public class UIRealmsResource {

    private final IAMShieldSession session;
    private final AdminPermissionEvaluator auth;

    public UIRealmsResource(IAMShieldSession session, AdminPermissionEvaluator auth) {
        this.session = session;
        this.auth = auth;
    }

    @GET
    @Path("names")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Lists only the names and display names of the realms",
            description = "Returns a list of realms containing only their name and displayName" +
                    " based on what the caller is allowed to view"
    )
    @APIResponse(
            responseCode = "200",
            description = "",
            content = {@Content(
                    schema = @Schema(
                            implementation = RealmNameRepresentation.class,
                            type = SchemaType.ARRAY
                    )
            )}
    )
    public Stream<RealmNameRepresentation> getRealms(@QueryParam("first") @DefaultValue("0") int first,
                                                     @QueryParam("max") @DefaultValue("10") int max,
                                                     @QueryParam("search") @DefaultValue("") String search) {
        final RealmsPermissionEvaluator eval = AdminPermissions.realms(session, auth.adminAuth());

        return session.realms().getRealmsStream(search)
                .filter(realm -> eval.canView(realm) || eval.isAdmin(realm))
                .skip(first)
                .limit(max)
                .map((RealmModel realm) -> new RealmNameRepresentation(realm.getName(), realm.getDisplayName()));
    }
}
