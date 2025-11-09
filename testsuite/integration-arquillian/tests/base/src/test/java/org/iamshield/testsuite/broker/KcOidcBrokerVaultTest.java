package org.iamshield.testsuite.broker;

import org.iamshield.testsuite.arquillian.annotation.EnableVault;

/**
 * @author Martin Kanis <mkanis@redhat.com>
 */
@EnableVault
public class KcOidcBrokerVaultTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcOidcBrokerVaultConfiguration.INSTANCE;
    }
}
