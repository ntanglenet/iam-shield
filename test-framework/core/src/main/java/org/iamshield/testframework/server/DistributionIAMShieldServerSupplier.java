package org.iamshield.testframework.server;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

public class DistributionIAMShieldServerSupplier extends AbstractIAMShieldServerSupplier {

    private static final Logger LOGGER = Logger.getLogger(DistributionIAMShieldServerSupplier.class);

    @ConfigProperty(name = "debug", defaultValue = "false")
    boolean debug = false;

    @Override
    public IAMShieldServer getServer() {
        return new DistributionIAMShieldServer(debug);
    }

    @Override
    public boolean requiresDatabase() {
        return true;
    }

    @Override
    public String getAlias() {
        return "distribution";
    }

    @Override
    public Logger getLogger() {
        return LOGGER;
    }
}
