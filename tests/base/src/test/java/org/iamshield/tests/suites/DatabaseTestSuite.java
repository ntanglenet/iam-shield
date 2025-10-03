package org.iamshield.tests.suites;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectPackages({"org.iamshield.tests.admin", "org.iamshield.tests.db"})
public class DatabaseTestSuite {
}
