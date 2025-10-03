package org.iamshield.testframework.events;

import org.iamshield.testframework.annotations.InjectEvents;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.RealmConfigBuilder;

public class EventsSupplier extends AbstractEventsSupplier<Events, InjectEvents> {

    @Override
    public Events getValue(InstanceContext<Events, InjectEvents> instanceContext) {
        return super.getValue(instanceContext);
    }

    @Override
    protected Events createValue(ManagedRealm realm) {
        return new Events(realm);
    }

    @Override
    public RealmConfigBuilder intercept(RealmConfigBuilder realm, InstanceContext<Events, InjectEvents> instanceContext) {
        return realm.eventsEnabled(true);
    }

}
