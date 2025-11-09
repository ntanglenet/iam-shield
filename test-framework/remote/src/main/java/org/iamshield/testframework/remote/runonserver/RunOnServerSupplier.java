package org.iamshield.testframework.remote.runonserver;

import org.apache.http.client.HttpClient;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.remote.RemoteProviders;

import java.util.Arrays;
import java.util.HashSet;

public class RunOnServerSupplier implements Supplier<RunOnServerClient, InjectRunOnServer> {

    @Override
    public RunOnServerClient getValue(InstanceContext<RunOnServerClient, InjectRunOnServer> instanceContext) {
        HttpClient httpClient = instanceContext.getDependency(HttpClient.class);
        ManagedRealm realm = instanceContext.getDependency(ManagedRealm.class, instanceContext.getAnnotation().realmRef());
        instanceContext.getDependency(RemoteProviders.class);

        TestClassServer testClassServer = instanceContext.getDependency(TestClassServer.class);
        String[] permittedPackages = instanceContext.getAnnotation().permittedPackages();
        testClassServer.addPermittedPackages(new HashSet<>(Arrays.asList(permittedPackages)));

        return new RunOnServerClient(httpClient, realm.getBaseUrl());
    }

    @Override
    public boolean compatible(InstanceContext<RunOnServerClient, InjectRunOnServer> a, RequestedInstance<RunOnServerClient, InjectRunOnServer> b) {
        return a.getAnnotation().realmRef().equals(b.getAnnotation().realmRef());
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.METHOD;
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_KEYCLOAK_SERVER;
    }

}
