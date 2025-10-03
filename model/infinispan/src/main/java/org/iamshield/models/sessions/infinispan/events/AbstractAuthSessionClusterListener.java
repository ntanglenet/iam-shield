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
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.sessions.infinispan.InfinispanAuthenticationSessionProvider;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.sessions.AuthenticationSessionProvider;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractAuthSessionClusterListener <SE extends SessionClusterEvent> implements ClusterListener {

    private static final Logger log = Logger.getLogger(AbstractAuthSessionClusterListener.class);

    private final IAMShieldSessionFactory sessionFactory;

    public AbstractAuthSessionClusterListener(IAMShieldSessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }


    @Override
    public void eventReceived(ClusterEvent event) {
        IAMShieldModelUtils.runJobInTransaction(sessionFactory, (IAMShieldSession session) -> {
            InfinispanAuthenticationSessionProvider provider = (InfinispanAuthenticationSessionProvider) session.getProvider(AuthenticationSessionProvider.class,
                    InfinispanUtils.EMBEDDED_PROVIDER_ID);
            SE sessionEvent = (SE) event;

            if (!provider.getCache().getStatus().allowInvocations()) {
                log.debugf("Cache in state '%s' doesn't allow invocations", provider.getCache().getStatus());
                return;
            }

            log.debugf("Received authentication session event '%s'", sessionEvent.toString());

            eventReceived(provider, sessionEvent);

        });
    }

    protected abstract void eventReceived(InfinispanAuthenticationSessionProvider provider, SE sessionEvent);
}
