package org.iamshield.protocol.docker.mapper;

import org.iamshield.models.AuthenticatedClientSessionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.representations.docker.DockerResponseToken;

public interface DockerAuthV2AttributeMapper {

    boolean appliesTo(DockerResponseToken responseToken);

    DockerResponseToken transformDockerResponseToken(DockerResponseToken responseToken, ProtocolMapperModel mappingModel,
                                                     IAMShieldSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession);
}
