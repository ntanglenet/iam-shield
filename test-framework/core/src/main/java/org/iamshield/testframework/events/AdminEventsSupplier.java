package org.iamshield.testframework.events;

import org.iamshield.testframework.annotations.InjectAdminEvents;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.RealmConfigBuilder;

public class AdminEventsSupplier extends AbstractEventsSupplier<AdminEvents, InjectAdminEvents> {

    @Override
    public AdminEvents getValue(InstanceContext<AdminEvents, InjectAdminEvents> instanceContext) {
        return super.getValue(instanceContext);
    }

    @Override
    public AdminEvents createValue(ManagedRealm realm) {
        return new AdminEvents(realm);
    }

    @Override
    public RealmConfigBuilder intercept(RealmConfigBuilder realm, InstanceContext<AdminEvents, InjectAdminEvents> instanceContext) {
        return realm.adminEventsEnabled(true).adminEventsDetailsEnabled(true);
    }

}
