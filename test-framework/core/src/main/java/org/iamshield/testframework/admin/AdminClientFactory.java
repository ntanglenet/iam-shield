package org.iamshield.testframework.admin;

import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.IAMShieldBuilder;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

public class AdminClientFactory {

    private final Supplier<IAMShieldBuilder> delegateSupplier;

    private final List<IAMShield> instanceToClose = new LinkedList<>();

    AdminClientFactory(String serverUrl) {
        delegateSupplier = () -> IAMShieldBuilder.builder().serverUrl(serverUrl);
    }

    public AdminClientBuilder create() {
        return new AdminClientBuilder(this, delegateSupplier.get());
    }

    void addToClose(IAMShield keycloak) {
        instanceToClose.add(keycloak);
    }

    public void close() {
        instanceToClose.forEach(IAMShield::close);
    }

}
