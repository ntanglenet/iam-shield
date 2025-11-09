package org.iamshield.testsuite.theme;

import org.junit.Assert;
import org.junit.Test;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.services.resource.AccountResourceProvider;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.theme.CustomAccountResourceProviderFactory;

public class CustomAccountResourceProviderTest extends AbstractTestRealmIAMShieldTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {

    }

    @Test
    public void testProviderOverride() {
        testingClient.server().run(session -> {
            AccountResourceProvider arp = session.getProvider(AccountResourceProvider.class, "ext-custom-account-console");
            Assert.assertTrue(arp instanceof CustomAccountResourceProviderFactory);
        });
    }

}
