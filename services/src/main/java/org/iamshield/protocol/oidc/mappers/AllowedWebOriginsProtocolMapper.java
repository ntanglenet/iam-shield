/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.iamshield.models.ClientModel;
import org.iamshield.models.ClientSessionContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.models.utils.ModelToRepresentation;
import org.iamshield.models.utils.RepresentationToModel;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.protocol.oidc.utils.WebOriginsUtils;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.representations.AccessToken;

import static org.iamshield.protocol.oidc.mappers.OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN;
import static org.iamshield.protocol.oidc.mappers.OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION;

/**
 * Protocol mapper to add allowed web origins to the access token to the 'allowed-origins' claim
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AllowedWebOriginsProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, TokenIntrospectionTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();


    public static final String PROVIDER_ID = "oidc-allowed-origins-mapper";

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, AllowedWebOriginsProtocolMapper.class);
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Allowed Web Origins";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Adds all allowed web origins to the 'allowed-origins' claim in the token";
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, IAMShieldSession session,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        boolean shouldUseLightweightToken = getShouldUseLightweightToken(session);
        boolean includeInAccessToken = shouldUseLightweightToken ?  OIDCAttributeMapperHelper.includeInLightweightAccessToken(mappingModel) : includeInAccessToken(mappingModel);
        if (!includeInAccessToken){
            return token;
        }
        setWebOrigin(token, session, clientSessionCtx);
        return token;
    }

    private boolean includeInAccessToken(ProtocolMapperModel mappingModel) {
        String includeInAccessToken = mappingModel.getConfig().get(INCLUDE_IN_ACCESS_TOKEN);

        // Backwards compatibility
        if (includeInAccessToken == null) {
            return true;
        }

        return "true".equals(includeInAccessToken);
    }

    @Override
    public AccessToken transformIntrospectionToken(AccessToken token, ProtocolMapperModel mappingModel, IAMShieldSession session,
                                                   UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        if (!includeInIntrospection(mappingModel)) {
            return token;
        }
        setWebOrigin(token, session, clientSessionCtx);
        return token;
    }

    private boolean includeInIntrospection(ProtocolMapperModel mappingModel) {
        String includeInIntrospection = mappingModel.getConfig().get(INCLUDE_IN_INTROSPECTION);

        // Backwards compatibility
        if (includeInIntrospection == null) {
            return true;
        }

        return "true".equals(includeInIntrospection);
    }

    @Override
    public ProtocolMapperModel getEffectiveModel(IAMShieldSession session, RealmModel realm, ProtocolMapperModel protocolMapperModel) {
        // Effectively clone
        ProtocolMapperModel copy = RepresentationToModel.toModel(ModelToRepresentation.toRepresentation(protocolMapperModel));

        copy.getConfig().put(INCLUDE_IN_ACCESS_TOKEN, String.valueOf(includeInAccessToken(copy)));
        copy.getConfig().put(INCLUDE_IN_INTROSPECTION, String.valueOf(includeInIntrospection(copy)));

        return copy;
    }

    private void setWebOrigin(AccessToken token, IAMShieldSession session, ClientSessionContext clientSessionCtx) {
        ClientModel client = clientSessionCtx.getClientSession().getClient();

        Set<String> allowedOrigins = client.getWebOrigins();
        if (allowedOrigins != null && !allowedOrigins.isEmpty()) {
            token.setAllowedOrigins(WebOriginsUtils.resolveValidWebOrigins(session, client));
        }
    }

    public static ProtocolMapperModel createClaimMapper(String name, boolean accessToken, boolean introspectionEndpoint) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken) {
            config.put(INCLUDE_IN_ACCESS_TOKEN, "true");
        } else {
            config.put(INCLUDE_IN_ACCESS_TOKEN, "false");
        }
        if (introspectionEndpoint) {
            config.put(INCLUDE_IN_INTROSPECTION, "true");
        } else {
            config.put(INCLUDE_IN_INTROSPECTION, "false");
        }
        mapper.setConfig(config);
        return mapper;
    }

}
