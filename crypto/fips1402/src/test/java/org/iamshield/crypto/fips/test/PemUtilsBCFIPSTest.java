package org.iamshield.crypto.fips.test;

import org.junit.Assume;
import org.junit.Before;
import org.iamshield.common.util.Environment;
import org.iamshield.util.PemUtilsTest;

public class PemUtilsBCFIPSTest extends PemUtilsTest {

    @Before
    public void before() {
        // Run this test just if java is in FIPS mode
        Assume.assumeTrue("Java is not in FIPS mode. Skipping the test.", Environment.isJavaInFipsMode());
    }
}

