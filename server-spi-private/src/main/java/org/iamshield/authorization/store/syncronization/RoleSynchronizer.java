package org.iamshield.authorization.store.syncronization;

import org.iamshield.authorization.fgap.AdminPermissionsSchema;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RoleContainerModel.RoleRemovedEvent;
import org.iamshield.provider.ProviderFactory;

public class RoleSynchronizer implements Synchronizer<RoleRemovedEvent> {

    @Override
    public void synchronize(RoleRemovedEvent event, IAMShieldSessionFactory factory) {
        ProviderFactory<AuthorizationProvider> providerFactory = factory.getProviderFactory(AuthorizationProvider.class);
        AuthorizationProvider authorizationProvider = providerFactory.create(event.getIAMShieldSession());

        AdminPermissionsSchema.SCHEMA.removeResourceObject(authorizationProvider, event);
    }
}
