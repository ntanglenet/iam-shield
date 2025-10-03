package org.iamshield.tests.admin.realm;

import org.iamshield.admin.client.IAMShield;
import org.iamshield.testframework.admin.AdminClientFactory;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.InjectAdminClientFactory;
import org.iamshield.testframework.annotations.InjectAdminEvents;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.events.AdminEvents;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;

public class AbstractRealmTest {

    @InjectRealm(ref = "managedRealm")
    ManagedRealm managedRealm;

    @InjectAdminClient(ref = "managed", realmRef = "managedRealm")
    IAMShield adminClient;

    @InjectAdminClientFactory
    AdminClientFactory adminClientFactory;

    @InjectRunOnServer(ref = "managed", realmRef = "managedRealm")
    RunOnServerClient runOnServer;

    @InjectAdminEvents(ref = "managedEvents", realmRef = "managedRealm")
    AdminEvents adminEvents;
}
