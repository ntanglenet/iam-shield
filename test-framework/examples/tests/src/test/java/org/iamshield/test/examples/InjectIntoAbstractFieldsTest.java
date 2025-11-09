package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;

@IAMShieldIntegrationTest
public class InjectIntoAbstractFieldsTest extends AbstractTest {

    @Test
    public void testManagedRealm() {
        Assertions.assertNotNull(realm);
    }

}
