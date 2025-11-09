/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.models.jpa;

import org.iamshield.Config;
import org.iamshield.connections.jpa.JpaConnectionProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmProviderFactory;

import jakarta.persistence.EntityManager;
import org.iamshield.models.ClientModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RealmProvider;
import org.iamshield.models.RoleContainerModel;
import org.iamshield.models.RoleContainerModel.RoleRemovedEvent;
import org.iamshield.models.RoleModel;
import org.iamshield.provider.ProviderEvent;
import org.iamshield.provider.ProviderEventListener;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JpaRealmProviderFactory implements RealmProviderFactory, ProviderEventListener {

    private Runnable onClose;

    public static final String PROVIDER_ID = "jpa";
    public static final int PROVIDER_PRIORITY = 1;

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        factory.register(this);
        onClose = () -> factory.unregister(this);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public JpaRealmProvider create(IAMShieldSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new JpaRealmProvider(session, em, null, null);
    }

    @Override
    public void close() {
        if (onClose != null) {
            onClose.run();
        }
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof RoleContainerModel.RoleRemovedEvent) {
            RoleRemovedEvent e = (RoleContainerModel.RoleRemovedEvent) event;
            RoleModel role = e.getRole();
            RoleContainerModel container = role.getContainer();
            RealmModel realm;
            if (container instanceof RealmModel) {
                realm = (RealmModel) container;
            } else if (container instanceof ClientModel) {
                realm = ((ClientModel) container).getRealm();
            } else {
                return;
            }
            ((JpaRealmProvider) e.getIAMShieldSession().getProvider(RealmProvider.class)).preRemove(realm, role);
        }
    }

    @Override
    public int order() {
        return PROVIDER_PRIORITY;
    }

}
