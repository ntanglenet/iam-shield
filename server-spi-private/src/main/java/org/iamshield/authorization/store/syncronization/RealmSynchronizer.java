/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.authorization.store.syncronization;

import org.iamshield.authorization.AuthorizationProvider;
import org.iamshield.authorization.store.ResourceServerStore;
import org.iamshield.authorization.store.StoreFactory;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel.RealmRemovedEvent;
import org.iamshield.provider.ProviderFactory;

/*
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RealmSynchronizer implements Synchronizer<RealmRemovedEvent> {
    @Override
    public void synchronize(RealmRemovedEvent event, IAMShieldSessionFactory factory) {
        ProviderFactory<AuthorizationProvider> providerFactory = factory.getProviderFactory(AuthorizationProvider.class);
        AuthorizationProvider authorizationProvider = providerFactory.create(event.getIAMShieldSession());
        StoreFactory storeFactory = authorizationProvider.getStoreFactory();
        ResourceServerStore resourceServerStore = storeFactory.getResourceServerStore();

        event.getRealm().getClientsStream().forEach(resourceServerStore::delete);
    }
}
