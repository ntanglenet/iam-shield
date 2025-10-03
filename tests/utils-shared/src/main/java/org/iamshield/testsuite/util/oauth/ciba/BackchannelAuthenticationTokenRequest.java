package org.iamshield.testsuite.util.oauth.ciba;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.iamshield.OAuth2Constants;
import org.iamshield.testsuite.util.oauth.AbstractHttpPostRequest;
import org.iamshield.testsuite.util.oauth.AbstractOAuthClient;
import org.iamshield.testsuite.util.oauth.AccessTokenResponse;

import java.io.IOException;

import static org.iamshield.protocol.oidc.grants.ciba.CibaGrantType.AUTH_REQ_ID;

public class BackchannelAuthenticationTokenRequest extends AbstractHttpPostRequest<BackchannelAuthenticationTokenRequest, AccessTokenResponse> {

    private final String authReqId;

    BackchannelAuthenticationTokenRequest(String authReqId, AbstractOAuthClient<?> client) {
        super(client);
        this.authReqId = authReqId;
    }

    @Override
    protected String getEndpoint() {
        return client.getEndpoints().getToken();
    }

    protected void initRequest() {
        parameter(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CIBA_GRANT_TYPE);
        parameter(AUTH_REQ_ID, authReqId);
    }

    @Override
    protected AccessTokenResponse toResponse(CloseableHttpResponse response) throws IOException {
        return new AccessTokenResponse(response);
    }

}
