package org.iamshield.protocol.docker.mapper;

import org.iamshield.models.AuthenticatedClientSessionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.protocol.docker.DockerAuthV2Protocol;
import org.iamshield.representations.docker.DockerAccess;
import org.iamshield.representations.docker.DockerResponseToken;

/**
 * Populates token with requested scope.  If more scopes are present than what has been requested, they will be removed.
 */
public class AllowAllDockerProtocolMapper extends DockerAuthV2ProtocolMapper implements DockerAuthV2AttributeMapper {

    public static final String PROVIDER_ID = "docker-v2-allow-all-mapper";

    @Override
    public String getDisplayType() {
        return "Allow All";
    }

    @Override
    public String getHelpText() {
        return "Allows all grants, returning the full set of requested access attributes as permitted attributes.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean appliesTo(final DockerResponseToken responseToken) {
        return true;
    }

    @Override
    public DockerResponseToken transformDockerResponseToken(final DockerResponseToken responseToken, final ProtocolMapperModel mappingModel,
                                                            final IAMShieldSession session, final UserSessionModel userSession, final AuthenticatedClientSessionModel clientSession) {

        responseToken.getAccessItems().clear();

        final String requestedScopes = clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM);
        if (requestedScopes != null) {
            for (String requestedScope : requestedScopes.split(" ")) {
                final DockerAccess requestedAccess = new DockerAccess(requestedScope);
                responseToken.getAccessItems().add(requestedAccess);
            }
        }

        return responseToken;
    }
}
