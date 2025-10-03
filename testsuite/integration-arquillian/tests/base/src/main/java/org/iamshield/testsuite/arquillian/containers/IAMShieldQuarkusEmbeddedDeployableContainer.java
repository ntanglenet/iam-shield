package org.iamshield.testsuite.arquillian.containers;

import java.util.List;
import org.jboss.arquillian.container.spi.client.container.LifecycleException;
import org.jboss.logging.Logger;
import org.iamshield.IAMShield;
import org.iamshield.common.Version;

/**
 * @author mhajas
 */
public class IAMShieldQuarkusEmbeddedDeployableContainer extends AbstractQuarkusDeployableContainer {

    private static final Logger log = Logger.getLogger(IAMShieldQuarkusEmbeddedDeployableContainer.class);
    
    private static final String KEYCLOAK_VERSION = Version.VERSION;

    private IAMShield iamshield;

    @Override
    public void start() throws LifecycleException {
        try {
            List<String> args = getArgs();
            log.debugf("Quarkus process arguments: %s", args);
            iamshield = configure().start(args);
            waitForReadiness();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void stop() throws LifecycleException {
        if (iamshield != null) {
            try {
                iamshield.stop();
            } catch (Exception e) {
                throw new RuntimeException("Failed to stop the server", e);
            } finally {
                iamshield = null;
            }
        }
    }

    private IAMShield.Builder configure() {
        return IAMShield.builder()
                .setHomeDir(configuration.getProvidersPath())
                .setVersion(KEYCLOAK_VERSION)
                .addDependency("org.iamshield.testsuite", "integration-arquillian-testsuite-providers", KEYCLOAK_VERSION)
                .addDependency("org.iamshield.testsuite", "integration-arquillian-testsuite-providers-deployment", KEYCLOAK_VERSION)
                .addDependency("org.iamshield.testsuite", "integration-arquillian-tests-base", KEYCLOAK_VERSION)
                .addDependency("org.iamshield.testsuite", "integration-arquillian-tests-base", KEYCLOAK_VERSION, "tests");
    }

    @Override
    protected List<String> configureArgs(List<String> args) {
        System.setProperty("quarkus.http.test-port", String.valueOf(configuration.getBindHttpPort()));
        System.setProperty("quarkus.http.test-ssl-port", String.valueOf(configuration.getBindHttpsPort()));
        return args;
    }

    @Override
    protected void checkLiveness() {
        // no-op, IAMShield would throw an exception in the test JVM if something went wrong
    }
}
