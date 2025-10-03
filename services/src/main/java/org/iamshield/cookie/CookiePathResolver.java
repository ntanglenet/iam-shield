package org.iamshield.cookie;

import org.iamshield.models.IAMShieldContext;
import org.iamshield.services.resources.RealmsResource;

class CookiePathResolver {

    private final IAMShieldContext context;
    private String realmPath;

    private String requestPath;

    CookiePathResolver(IAMShieldContext context) {
        this.context = context;
    }

    String resolvePath(CookieType cookieType) {
        switch (cookieType.getPath()) {
            case REALM:
                if (realmPath == null) {
                    realmPath = RealmsResource.realmBaseUrl(context.getUri()).path("/").build(context.getRealm().getName()).getRawPath();
                }
                return realmPath;
            case REQUEST:
                if (requestPath == null) {
                    requestPath = context.getUri().getRequestUri().getRawPath();
                }
                return requestPath;
            default:
                throw new IllegalArgumentException("Unsupported enum value " + cookieType.getPath().name());
        }
    }

}
