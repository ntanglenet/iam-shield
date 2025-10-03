package org.iamshield.protocol.saml.mappers;

import org.iamshield.models.AuthenticatedClientSessionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.UserSessionModel;

public interface SAMLNameIdMapper {

    String mapperNameId(String nameIdFormat, ProtocolMapperModel mappingModel, IAMShieldSession session,
                                        UserSessionModel userSession, AuthenticatedClientSessionModel clientSession);

}