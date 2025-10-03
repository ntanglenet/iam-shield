package org.iamshield.authorization.store.syncronization;

import org.iamshield.authorization.fgap.AdminPermissionsSchema;
import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.models.GroupModel.GroupRemovedEvent;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderFactory;

public class GroupSynchronizer implements Synchronizer<GroupRemovedEvent> {

    @Override
    public void synchronize(GroupRemovedEvent event, IAMShieldSessionFactory factory) {
        ProviderFactory<AuthorizationProvider> providerFactory = factory.getProviderFactory(AuthorizationProvider.class);
        AuthorizationProvider authorizationProvider = providerFactory.create(event.getIAMShieldSession());

        AdminPermissionsSchema.SCHEMA.removeResourceObject(authorizationProvider, event);
    }
}
