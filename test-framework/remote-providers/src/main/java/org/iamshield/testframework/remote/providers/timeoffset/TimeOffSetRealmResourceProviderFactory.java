package org.iamshield.testframework.remote.providers.timeoffset;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.services.resource.RealmResourceProvider;
import org.iamshield.services.resource.RealmResourceProviderFactory;

public class TimeOffSetRealmResourceProviderFactory implements RealmResourceProviderFactory {

    private final String ID = "testing-timeoffset";

    @Override
    public RealmResourceProvider create(IAMShieldSession session) {
        return new TimeOffSetRealmResourceProvider(session);
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void init(org.iamshield.Config.Scope config) {

    }
}
