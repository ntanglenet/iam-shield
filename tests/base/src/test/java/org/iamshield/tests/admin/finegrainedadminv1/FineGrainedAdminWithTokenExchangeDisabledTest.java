package org.iamshield.tests.admin.finegrainedadminv1;

import org.junit.jupiter.api.Test;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;

@IAMShieldIntegrationTest(config = AbstractFineGrainedAdminTest.FineGrainedAdminServerConf.class)
public class FineGrainedAdminWithTokenExchangeDisabledTest extends AbstractFineGrainedAdminTest{

    @Test
    public void testTokenExchangeDisabled() {
        checkTokenExchange(false);
    }
}
