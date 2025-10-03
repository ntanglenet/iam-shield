package org.iamshield.representations;

import org.iamshield.TokenCategory;

public class AuthorizationResponseToken extends JsonWebToken{

    @Override
    public TokenCategory getCategory() {
        return TokenCategory.AUTHORIZATION_RESPONSE;
    }
}
