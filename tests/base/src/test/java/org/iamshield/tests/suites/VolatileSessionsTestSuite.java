package org.iamshield.tests.suites;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.iamshield.common.Profile;
import org.iamshield.testframework.injection.SuiteSupport;
import org.iamshield.testframework.server.IAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfigBuilder;
import org.iamshield.tests.admin.ClientTest;

@Suite
@SelectClasses(ClientTest.class)
public class VolatileSessionsTestSuite {

    @BeforeSuite
    public static void beforeSuite() {
        SuiteSupport.startSuite()
                .registerServerConfig(VolatileSessionsServerConfig.class);
    }

    @AfterSuite
    public static void afterSuite() {
        SuiteSupport.stopSuite();
    }

    public static class VolatileSessionsServerConfig implements IAMShieldServerConfig {

        @Override
        public IAMShieldServerConfigBuilder configure(IAMShieldServerConfigBuilder config) {
            return config.featuresDisabled(Profile.Feature.PERSISTENT_USER_SESSIONS);
        }
    }
}
