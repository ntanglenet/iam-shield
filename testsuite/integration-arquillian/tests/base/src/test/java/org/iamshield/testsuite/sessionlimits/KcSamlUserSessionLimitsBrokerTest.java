package org.iamshield.testsuite.sessionlimits;

import org.iamshield.testsuite.broker.BrokerConfiguration;
import org.iamshield.testsuite.broker.KcSamlBrokerConfiguration;

public class KcSamlUserSessionLimitsBrokerTest extends AbstractUserSessionLimitsBrokerTest {
    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcSamlBrokerConfiguration.INSTANCE;
    }
}
