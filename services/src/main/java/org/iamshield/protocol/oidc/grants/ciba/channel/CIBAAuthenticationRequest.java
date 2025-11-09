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
 *
 */
package org.iamshield.protocol.oidc.grants.ciba.channel;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.iamshield.OAuth2Constants;
import org.iamshield.crypto.Algorithm;
import org.iamshield.crypto.KeyUse;
import org.iamshield.crypto.SignatureProvider;
import org.iamshield.crypto.SignatureSignerContext;
import org.iamshield.jose.jwe.JWEException;
import org.iamshield.jose.jws.JWSBuilder;
import org.iamshield.models.ClientModel;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.protocol.oidc.grants.ciba.CibaGrantType;
import org.iamshield.representations.IDToken;
import org.iamshield.representations.JsonWebToken;
import org.iamshield.services.Urls;
import org.iamshield.util.TokenUtil;

/**
 * <p>Represents an authentication request sent by a consumption device (CD).
 *
 * <p>A authentication request can be serialized to a JWE so that it can be exchanged with authentication devices (AD)
 * to communicate and authorize the authentication request made by consumption devices (CDs).
 * 
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class CIBAAuthenticationRequest extends JsonWebToken {

    /**
     * Deserialize the given {@code jwe} to a {@link CIBAAuthenticationRequest} instance.
     *
     * @param session the session
     * @param jwe the authentication request in JWE format.
     * @return the authentication request instance
     * @throws Exception
     */
    public static CIBAAuthenticationRequest deserialize(IAMShieldSession session, String jwe) {
        SecretKey aesKey = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.ENC, Algorithm.AES).getSecretKey();
        SecretKey hmacKey = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, Constants.INTERNAL_SIGNATURE_ALGORITHM).getSecretKey();

        try {
            byte[] contentBytes = TokenUtil.jweDirectVerifyAndDecode(aesKey, hmacKey, jwe);
            jwe = new String(contentBytes, StandardCharsets.UTF_8);
        } catch (JWEException e) {
            throw new RuntimeException("Error decoding auth_req_id.", e);
        }

        return session.tokens().decode(jwe, CIBAAuthenticationRequest.class);
    }

    public static final String SESSION_STATE = IDToken.SESSION_STATE;
    public static final String AUTH_RESULT_ID = "auth_result_id";

    @JsonProperty(OAuth2Constants.SCOPE)
    protected String scope;

    @JsonProperty(AUTH_RESULT_ID)
    protected String authResultId;

    @JsonProperty(CibaGrantType.BINDING_MESSAGE)
    protected String bindingMessage;

    @JsonProperty(OAuth2Constants.ACR_VALUES)
    protected String acrValues;

    @JsonIgnore
    protected ClientModel client;

    @JsonIgnore
    protected String clientNotificationToken;

    @JsonIgnore
    protected UserModel user;

    public CIBAAuthenticationRequest() {
        // for reflection
    }

    public CIBAAuthenticationRequest(IAMShieldSession session, UserModel user, ClientModel client) {
        id(IAMShieldModelUtils.generateId());
        issuedNow();
        RealmModel realm = session.getContext().getRealm();
        issuer(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        audience(getIssuer());
        subject(user.getId());
        issuedFor(client.getClientId());
        setAuthResultId(IAMShieldModelUtils.generateId());
        setClient(client);
        setUser(user);
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getAuthResultId() {
        return authResultId;
    }

    public void setAuthResultId(String authResultId) {
        this.authResultId = authResultId;
    }

    public String getBindingMessage() {
        return bindingMessage;
    }

    public void setBindingMessage(String binding_message) {
        this.bindingMessage = binding_message;
    }

    public String getAcrValues() {
        return acrValues;
    }

    public void setAcrValues(String acrValues) {
        this.acrValues = acrValues;
    }

    /**
     * Serializes this instance to a JWE.
     *
     * @param session the session
     * @return the JWE
     */
    public String serialize(IAMShieldSession session) {
        try {
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, Constants.INTERNAL_SIGNATURE_ALGORITHM);
            SignatureSignerContext signer = signatureProvider.signer();
            String encodedJwt = new JWSBuilder().type("JWT").jsonContent(this).sign(signer);
            SecretKey aesKey = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.ENC, Algorithm.AES).getSecretKey();
            SecretKey hmacKey = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, Constants.INTERNAL_SIGNATURE_ALGORITHM).getSecretKey();

            return TokenUtil.jweDirectEncode(aesKey, hmacKey, encodedJwt.getBytes(StandardCharsets.UTF_8));
        } catch (JWEException e) {
            throw new RuntimeException("Error encoding auth_req_id.", e);
        }
    }

    public void setClient(ClientModel client) {
        this.client = client;
    }

    public ClientModel getClient() {
        return client;
    }

    public String getClientNotificationToken() {
        return clientNotificationToken;
    }

    public void setClientNotificationToken(String clientNotificationToken) {
        this.clientNotificationToken = clientNotificationToken;
    }

    public void setUser(UserModel user) {
        this.user = user;
    }

    public UserModel getUser() {
        return user;
    }
}
