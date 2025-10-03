package org.iamshield.testframework.remote.providers.runonserver;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.services.resource.RealmResourceProvider;
import org.iamshield.services.resource.RealmResourceProviderFactory;

import java.net.MalformedURLException;

public class RunOnServerRealmResourceProviderFactory implements RealmResourceProviderFactory {

    private static final String ID = "testing-run-on-server";

    private ClassLoader testClassLoader;

    @Override
    public RealmResourceProvider create(IAMShieldSession session) {
        return new RunOnServerRealmResourceProvider(session, testClassLoader);
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
        try {
            testClassLoader = new TestClassLoader();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

}
