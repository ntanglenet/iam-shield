package org.iamshield.testframework;

import org.iamshield.testframework.admin.AdminClientFactorySupplier;
import org.iamshield.testframework.admin.AdminClientSupplier;
import org.iamshield.testframework.infinispan.InfinispanExternalServerSupplier;
import org.iamshield.testframework.database.DevFileDatabaseSupplier;
import org.iamshield.testframework.database.DevMemDatabaseSupplier;
import org.iamshield.testframework.database.TestDatabase;
import org.iamshield.testframework.events.AdminEventsSupplier;
import org.iamshield.testframework.events.EventsSupplier;
import org.iamshield.testframework.events.SysLogServerSupplier;
import org.iamshield.testframework.http.HttpClientSupplier;
import org.iamshield.testframework.http.HttpServerSupplier;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.realm.ClientSupplier;
import org.iamshield.testframework.realm.RealmSupplier;
import org.iamshield.testframework.realm.UserSupplier;
import org.iamshield.testframework.server.DistributionIAMShieldServerSupplier;
import org.iamshield.testframework.server.EmbeddedIAMShieldServerSupplier;
import org.iamshield.testframework.server.IAMShieldServer;
import org.iamshield.testframework.server.IAMShieldUrlsSupplier;
import org.iamshield.testframework.server.RemoteIAMShieldServerSupplier;

import java.util.List;
import java.util.Map;

public class CoreTestFrameworkExtension implements TestFrameworkExtension {

    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(
                new AdminClientSupplier(),
                new AdminClientFactorySupplier(),
                new ClientSupplier(),
                new RealmSupplier(),
                new UserSupplier(),
                new DistributionIAMShieldServerSupplier(),
                new EmbeddedIAMShieldServerSupplier(),
                new RemoteIAMShieldServerSupplier(),
                new IAMShieldUrlsSupplier(),
                new DevMemDatabaseSupplier(),
                new DevFileDatabaseSupplier(),
                new SysLogServerSupplier(),
                new EventsSupplier(),
                new AdminEventsSupplier(),
                new HttpClientSupplier(),
                new HttpServerSupplier(),
                new InfinispanExternalServerSupplier()
        );
    }

    @Override
    public Map<Class<?>, String> valueTypeAliases() {
        return Map.of(
                IAMShieldServer.class, "server",
                TestDatabase.class, "database"
        );
    }

}
