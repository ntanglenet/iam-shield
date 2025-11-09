package org.iamshield.crypto.def.test;

import org.junit.Assume;
import org.junit.Before;
import org.iamshield.RSAVerifierTest;
import org.iamshield.common.util.Environment;

/**
 * Test with bouncycastle security provider
 * 
 */
public class DefaultCryptoRSAVerifierTest extends RSAVerifierTest {

    @Before
    public void before() {
        // Run this test just if java is not in FIPS mode
        Assume.assumeFalse("Java is in FIPS mode. Skipping the test.", Environment.isJavaInFipsMode());
    }
}
