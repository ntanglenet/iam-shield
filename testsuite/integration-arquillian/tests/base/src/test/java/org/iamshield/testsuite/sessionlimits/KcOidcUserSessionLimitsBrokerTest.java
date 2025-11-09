package org.iamshield.testsuite.sessionlimits;

import org.iamshield.testsuite.broker.BrokerConfiguration;
import org.iamshield.testsuite.broker.KcOidcBrokerConfiguration;

public class KcOidcUserSessionLimitsBrokerTest extends AbstractUserSessionLimitsBrokerTest {
    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcOidcBrokerConfiguration.INSTANCE;
    }
}
