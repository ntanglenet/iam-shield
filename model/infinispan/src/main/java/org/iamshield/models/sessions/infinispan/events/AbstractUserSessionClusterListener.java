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

package org.iamshield.models.sessions.infinispan.events;

import org.jboss.logging.Logger;
import org.iamshield.cluster.ClusterEvent;
import org.iamshield.cluster.ClusterListener;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.provider.Provider;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractUserSessionClusterListener<SE extends SessionClusterEvent, T extends Provider> implements ClusterListener {

    private static final Logger log = Logger.getLogger(AbstractUserSessionClusterListener.class);

    private final IAMShieldSessionFactory sessionFactory;

    private final Class<T> providerClazz;

    public AbstractUserSessionClusterListener(IAMShieldSessionFactory sessionFactory, Class<T> providerClazz) {
        this.sessionFactory = sessionFactory;
        this.providerClazz = providerClazz;
    }


    @Override
    public void eventReceived(ClusterEvent event) {
        IAMShieldModelUtils.runJobInTransaction(sessionFactory, (IAMShieldSession session) -> {
            T provider = session.getProvider(providerClazz);
            SE sessionEvent = (SE) event;

            if (log.isDebugEnabled()) {
                log.debugf("Received user session event '%s'.", sessionEvent.toString());
            }

            eventReceived(provider, sessionEvent);
        });
    }

    protected abstract void eventReceived(T provider, SE sessionEvent);
}
