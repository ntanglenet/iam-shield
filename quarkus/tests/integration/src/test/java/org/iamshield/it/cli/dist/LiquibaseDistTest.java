package org.iamshield.it.cli.dist;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.iamshield.it.junit5.extension.DistributionTest;
import org.iamshield.it.junit5.extension.RawDistOnly;
import org.iamshield.it.utils.IAMShieldDistribution;

@DistributionTest
@RawDistOnly(reason = "Containers are immutable")
@Tag(DistributionTest.SLOW)
public class LiquibaseDistTest {

    @Test
    public void dbLockMultipleExecution(IAMShieldDistribution distribution) {
        var result = distribution.run("start-dev", "--log-level=org.iamshield.connections.jpa.updater.liquibase.lock.CustomLockService:trace");
        result.assertMessage("Initialize Database Lock Table, current locks []");
        result.assertMessage("Initialized record in the database lock table");

        // the code block in the CustomLockService should not be executed for the second time
        result = distribution.run("start-dev", "--log-level=org.iamshield.connections.jpa.updater.liquibase.lock.CustomLockService:trace");
        result.assertNoMessage("Initialize Database Lock Table, current locks");
        result.assertNoMessage("Initialized record in the database lock table");
    }
}
