/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.testsuite.model;

import org.junit.Test;
import org.iamshield.common.util.Time;
import org.iamshield.events.Event;
import org.iamshield.events.EventStoreProvider;
import org.iamshield.events.EventType;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.ProviderFactory;

import static org.junit.Assert.assertEquals;

@RequireProvider(EventStoreProvider.class)
public class TimeOffsetTest extends IAMShieldModelTest {

    private String realmId;

    @Override
    protected void createEnvironment(IAMShieldSession s) {
        RealmModel r = s.realms().createRealm("realm");
        s.getContext().setRealm(r);
        r.setDefaultRole(s.roles().addRealmRole(r, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + r.getName()));
        r.setEventsExpiration(5);
        realmId = r.getId();
    }

    @Override
    protected void cleanEnvironment(IAMShieldSession s) {
        RealmModel r = s.realms().getRealm(realmId);
        s.getContext().setRealm(r);
        s.realms().removeRealm(realmId);
    }

    @Test
    public void testOffset() {
        withRealm(realmId, (session, realmModel) -> {
            EventStoreProvider provider = session.getProvider(EventStoreProvider.class);

            Event e = new Event();
            e.setType(EventType.LOGIN);
            e.setRealmId(realmId);
            e.setTime(Time.currentTimeMillis());
            provider.onEvent(e);
            return null;
        });

        withRealm(realmId, (session, realmModel) -> {
            EventStoreProvider provider = session.getProvider(EventStoreProvider.class);
            assertEquals(1, provider.createQuery().realm(realmId).getResultStream().count());

            setTimeOffset(5);

            // store requires explicit expiration of expired events
            ProviderFactory<EventStoreProvider> providerFactory = session.getIAMShieldSessionFactory().getProviderFactory(EventStoreProvider.class);
            if ("jpa".equals(providerFactory.getId())) {
                provider.clearExpiredEvents();
            }
            return null;
        });

        withRealm(realmId, (session, realmModel) -> {
            EventStoreProvider provider = session.getProvider(EventStoreProvider.class);
            assertEquals(0, provider.createQuery().realm(realmId).getResultStream().count());
            return null;
        });
    }
}
