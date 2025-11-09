package org.iamshield.testframework.admin;

import org.iamshield.OAuth2Constants;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testframework.TestFrameworkException;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.config.Config;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.ManagedUser;

public class AdminClientSupplier implements Supplier<IAMShield, InjectAdminClient> {

    @Override
    public IAMShield getValue(InstanceContext<IAMShield, InjectAdminClient> instanceContext) {
        InjectAdminClient annotation = instanceContext.getAnnotation();

        InjectAdminClient.Mode mode = annotation.mode();

        AdminClientBuilder adminBuilder = instanceContext.getDependency(AdminClientFactory.class).create()
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS);

        if (mode.equals(InjectAdminClient.Mode.BOOTSTRAP)) {
            adminBuilder.realm("master").clientId(Config.getAdminClientId()).clientSecret(Config.getAdminClientSecret());
        } else if (mode.equals(InjectAdminClient.Mode.MANAGED_REALM)) {
            ManagedRealm managedRealm = instanceContext.getDependency(ManagedRealm.class);
            adminBuilder.realm(managedRealm.getName());

            String clientId = !annotation.client().isEmpty() ? annotation.client() : null;
            String userId = !annotation.user().isEmpty() ? annotation.user() : null;

            if (clientId == null) {
                throw new TestFrameworkException("Client is required when using managed realm mode");
            }

            RealmRepresentation realmRep = managedRealm.getCreatedRepresentation();
            ClientRepresentation clientRep = realmRep.getClients().stream()
                    .filter(c -> c.getClientId().equals(annotation.client()))
                    .findFirst().orElseThrow(() -> new TestFrameworkException("Client " + annotation.client() + " not found in managed realm"));

            adminBuilder.clientId(clientId).clientSecret(clientRep.getSecret());

            if (userId != null) {
                UserRepresentation userRep = realmRep.getUsers().stream()
                        .filter(u -> u.getUsername().equals(annotation.user()))
                        .findFirst().orElseThrow(() -> new TestFrameworkException("User " + annotation.user() + " not found in managed realm"));
                String password = ManagedUser.getPassword(userRep);
                adminBuilder.username(userRep.getUsername()).password(password);
                adminBuilder.grantType(OAuth2Constants.PASSWORD);
            }
        }

        return adminBuilder.build();
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public boolean compatible(InstanceContext<IAMShield, InjectAdminClient> a, RequestedInstance<IAMShield, InjectAdminClient> b) {
        return true;
    }

    @Override
    public void close(InstanceContext<IAMShield, InjectAdminClient> instanceContext) {
        instanceContext.getValue().close();
    }

}
