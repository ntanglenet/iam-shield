package org.iamshield.it.storage.database.dist;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.iamshield.it.junit5.extension.CLIResult;
import org.iamshield.it.junit5.extension.DistributionTest;
import org.iamshield.it.junit5.extension.WithDatabase;
import org.iamshield.it.storage.database.MySQLTest;
import org.iamshield.it.utils.RawDistRootPath;
import org.iamshield.quarkus.runtime.cli.command.AbstractAutoBuildCommand;

import io.quarkus.test.junit.main.Launch;

@DistributionTest(removeBuildOptionsAfterBuild = true)
@WithDatabase(alias = "mysql")
public class MySQLDistTest extends MySQLTest {

    @Override
    @Tag(DistributionTest.STORAGE)
    @Test
    @Launch({ "start", AbstractAutoBuildCommand.OPTIMIZED_BUILD_OPTION_LONG, "--http-enabled=true", "--hostname-strict=false" })
    protected void testSuccessful(CLIResult result) {
        super.testSuccessful(result);
    }

    @Tag(DistributionTest.STORAGE)
    @Test
    @Launch({"start", AbstractAutoBuildCommand.OPTIMIZED_BUILD_OPTION_LONG, "--spi-connections-jpa-quarkus-migration-strategy=manual", "--spi-connections-jpa-quarkus-initialize-empty=false", "--http-enabled=true", "--hostname-strict=false",})
    public void testKeycloakDbUpdateScript(CLIResult cliResult, RawDistRootPath rawDistRootPath) {
        assertManualDbInitialization(cliResult, rawDistRootPath);
    }

    @Tag(DistributionTest.STORAGE)
    @Test
    @Launch({"start", AbstractAutoBuildCommand.OPTIMIZED_BUILD_OPTION_LONG, "--http-enabled=true", "--hostname-strict=false", "--db-pool-max-lifetime=28800"})
    public void testWarningForTooShortLifetime(CLIResult cliResult) {
        cliResult.assertMessage("set 'db-pool-max-lifetime' to a duration smaller than '28800' seconds.");
    }
}
