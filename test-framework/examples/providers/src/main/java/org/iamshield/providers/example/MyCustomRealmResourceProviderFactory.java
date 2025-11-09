package org.iamshield.providers.example;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.services.resource.RealmResourceProvider;
import org.iamshield.services.resource.RealmResourceProviderFactory;

/**
 *
 * @author <a href="mailto:svacek@redhat.com">Simon Vacek</a>
 */
public class MyCustomRealmResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "custom-provider";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(IAMShieldSession session) {
        return new MyCustomRealmResourceProvider(session);
    }

    @Override
    public void init(org.iamshield.Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }
}
