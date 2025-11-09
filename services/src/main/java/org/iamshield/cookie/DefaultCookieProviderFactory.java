package org.iamshield.cookie;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

public class DefaultCookieProviderFactory implements CookieProviderFactory {

    @Override
    public CookieProvider create(IAMShieldSession session) {
        return new DefaultCookieProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "default";
    }

}
