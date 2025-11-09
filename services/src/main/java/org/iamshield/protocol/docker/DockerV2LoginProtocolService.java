package org.iamshield.protocol.docker;

import org.iamshield.common.Profile;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.services.resources.RealmsResource;
import org.iamshield.utils.ProfileHelper;

import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

public class DockerV2LoginProtocolService {

    private final EventBuilder event;

    private final IAMShieldSession session;

    public DockerV2LoginProtocolService(final IAMShieldSession session, final EventBuilder event) {
        this.session = session;
        this.event = event;
    }

    public static UriBuilder authProtocolBaseUrl(final UriInfo uriInfo) {
        final UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        return authProtocolBaseUrl(baseUriBuilder);
    }

    public static UriBuilder authProtocolBaseUrl(final UriBuilder baseUriBuilder) {
        return baseUriBuilder.path(RealmsResource.class).path("{realm}/protocol/" + DockerAuthV2Protocol.LOGIN_PROTOCOL);
    }

    public static UriBuilder authUrl(final UriInfo uriInfo) {
        final UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        return authUrl(baseUriBuilder);
    }

    public static UriBuilder authUrl(final UriBuilder baseUriBuilder) {
        final UriBuilder uriBuilder = authProtocolBaseUrl(baseUriBuilder);
        return uriBuilder.path(DockerV2LoginProtocolService.class, "auth");
    }

    /**
     * Authorization endpoint
     */
    @Path("auth")
    public Object auth() {
        ProfileHelper.requireFeature(Profile.Feature.DOCKER);

        return new DockerEndpoint(session, event, EventType.LOGIN);
    }
}
