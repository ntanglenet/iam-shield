package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.remote.timeoffset.InjectTimeOffSet;
import org.iamshield.testframework.remote.timeoffset.TimeOffSet;

@IAMShieldIntegrationTest
public class TimeOffSetExampleTest {

    @InjectTimeOffSet(offset = 3)
    TimeOffSet timeOffSet;

    @Test
    public void testSetOffset() {
        int offset = timeOffSet.get();
        Assertions.assertEquals(3, offset);
        Assertions.assertDoesNotThrow(() -> timeOffSet.set(10));
        offset = timeOffSet.get();
        Assertions.assertEquals(10, offset);
    }

    @Test
    public void testGetOffset() {
        int offset = timeOffSet.get();
        Assertions.assertEquals(3, offset);
    }
}
