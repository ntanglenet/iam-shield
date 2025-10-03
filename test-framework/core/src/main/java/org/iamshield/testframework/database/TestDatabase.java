package org.iamshield.testframework.database;

import java.util.Map;

public interface TestDatabase {

    void start(DatabaseConfiguration databaseConfiguration);

    void stop();

    Map<String, String> serverConfig();
}
