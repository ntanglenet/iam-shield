package org.iamshield.protocol.oidc.mappers;

import org.iamshield.models.ClientSessionContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.representations.AccessToken;

public interface TokenIntrospectionTokenMapper {
    AccessToken transformIntrospectionToken(AccessToken token, ProtocolMapperModel mappingModel, IAMShieldSession session,
                                       UserSessionModel userSession, ClientSessionContext clientSessionCtx);
}
