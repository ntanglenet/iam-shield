package org.iamshield.protocol.oidc.mappers;

import org.iamshield.models.ClientSessionContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.representations.AccessTokenResponse;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface OIDCAccessTokenResponseMapper {

    AccessTokenResponse transformAccessTokenResponse(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel,
                                                     IAMShieldSession session, UserSessionModel userSession,
                                                     ClientSessionContext clientSessionCtx);
}
