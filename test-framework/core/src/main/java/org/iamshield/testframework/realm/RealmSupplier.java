package org.iamshield.testframework.realm;

import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.Registry;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierHelpers;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.injection.AbstractInterceptorHelper;
import org.iamshield.testframework.server.IAMShieldServer;

public class RealmSupplier implements Supplier<ManagedRealm, InjectRealm> {

    @Override
    public ManagedRealm getValue(InstanceContext<ManagedRealm, InjectRealm> instanceContext) {
        IAMShieldServer server = instanceContext.getDependency(IAMShieldServer.class);
        IAMShield adminClient = instanceContext.getDependency(IAMShield.class, "bootstrap-client");

        String attachTo = instanceContext.getAnnotation().attachTo();
        boolean managed = attachTo.isEmpty();

        RealmRepresentation realmRepresentation;

        if (managed) {
            RealmConfig config = SupplierHelpers.getInstance(instanceContext.getAnnotation().config());
            RealmConfigBuilder realmConfigBuilder = config.configure(RealmConfigBuilder.create());

            RealmConfigInterceptorHelper interceptor = new RealmConfigInterceptorHelper(instanceContext.getRegistry());
            realmConfigBuilder = interceptor.intercept(realmConfigBuilder, instanceContext);

            realmRepresentation = realmConfigBuilder.build();

            if (realmRepresentation.getRealm() == null) {
                realmRepresentation.setRealm(SupplierHelpers.createName(instanceContext));
            }

            if (realmRepresentation.getId() == null) {
                realmRepresentation.setId(realmRepresentation.getRealm());
            }

            adminClient.realms().create(realmRepresentation);

            // TODO Token needs to be invalidated after creating realm to have roles for new realm in the token. Maybe lightweight access tokens could help.
            adminClient.tokenManager().invalidate(adminClient.tokenManager().getAccessTokenString());
        } else {
            realmRepresentation = adminClient.realm(attachTo).toRepresentation();
        }

        instanceContext.addNote("managed", managed);

        RealmResource realmResource = adminClient.realm(realmRepresentation.getRealm());
        return new ManagedRealm(server.getBaseUrl() + "/realms/" + realmRepresentation.getRealm(), realmRepresentation, realmResource);
    }

    @Override
    public boolean compatible(InstanceContext<ManagedRealm, InjectRealm> a, RequestedInstance<ManagedRealm, InjectRealm> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public void close(InstanceContext<ManagedRealm, InjectRealm> instanceContext) {
        if (instanceContext.getNote("managed", Boolean.class)) {
            instanceContext.getValue().admin().remove();
        }
    }

    @Override
    public int order() {
        return SupplierOrder.REALM;
    }

    private static class RealmConfigInterceptorHelper extends AbstractInterceptorHelper<RealmConfigInterceptor, RealmConfigBuilder> {

        private RealmConfigInterceptorHelper(Registry registry) {
            super(registry, RealmConfigInterceptor.class);
        }

        @Override
        public RealmConfigBuilder intercept(RealmConfigBuilder value, Supplier<?, ?> supplier, InstanceContext<?, ?> existingInstance) {
            if (supplier instanceof RealmConfigInterceptor interceptor) {
                value = interceptor.intercept(value, existingInstance);
            }
            return value;
        }

    }

}
