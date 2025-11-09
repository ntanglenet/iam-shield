package org.iamshield.testframework.mail;

import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierOrder;
import org.iamshield.testframework.mail.annotations.InjectMailServer;
import org.iamshield.testframework.realm.RealmConfigBuilder;
import org.iamshield.testframework.realm.RealmConfigInterceptor;

public class GreenMailSupplier implements Supplier<MailServer, InjectMailServer>, RealmConfigInterceptor<MailServer, InjectMailServer> {

    private final String HOSTNAME = "localhost";
    private final int PORT = 3025;
    private final String FROM = "auto@keycloak.org";

    @Override
    public MailServer getValue(InstanceContext<MailServer, InjectMailServer> instanceContext) {
        return new MailServer(HOSTNAME, PORT);
    }

    @Override
    public void close(InstanceContext<MailServer, InjectMailServer> instanceContext) {
        instanceContext.getValue().stop();
    }

    @Override
    public boolean compatible(InstanceContext<MailServer, InjectMailServer> a, RequestedInstance<MailServer, InjectMailServer> b) {
        return true;
    }

    @Override
    public RealmConfigBuilder intercept(RealmConfigBuilder realm, InstanceContext<MailServer, InjectMailServer> instanceContext) {
        return realm.smtp(HOSTNAME, PORT, FROM);
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_REALM;
    }
}
