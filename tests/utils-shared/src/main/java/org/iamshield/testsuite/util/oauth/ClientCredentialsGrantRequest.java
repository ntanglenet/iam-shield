package org.iamshield.testsuite.util.oauth;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.iamshield.OAuth2Constants;
import org.iamshield.util.TokenUtil;

import java.io.IOException;

public class ClientCredentialsGrantRequest extends AbstractHttpPostRequest<ClientCredentialsGrantRequest, AccessTokenResponse> {

    ClientCredentialsGrantRequest(AbstractOAuthClient<?> client) {
        super(client);
    }

    public ClientCredentialsGrantRequest dpopProof(String dpopProof) {
        header(TokenUtil.TOKEN_TYPE_DPOP, dpopProof);
        return this;
    }

    @Override
    protected String getEndpoint() {
        return client.getEndpoints().getToken();
    }

    protected void initRequest() {
        parameter(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS);

        scope();
    }

    @Override
    protected AccessTokenResponse toResponse(CloseableHttpResponse response) throws IOException {
        return new AccessTokenResponse(response);
    }

}
