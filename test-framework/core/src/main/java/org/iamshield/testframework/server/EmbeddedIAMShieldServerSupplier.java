package org.iamshield.testframework.server;

import org.jboss.logging.Logger;

public class EmbeddedIAMShieldServerSupplier extends AbstractIAMShieldServerSupplier {

    private static final Logger LOGGER = Logger.getLogger(EmbeddedIAMShieldServerSupplier.class);

    @Override
    public IAMShieldServer getServer() {
        return new EmbeddedIAMShieldServer();
    }

    @Override
    public boolean requiresDatabase() {
        return true;
    }

    @Override
    public String getAlias() {
        return "embedded";
    }

    @Override
    public Logger getLogger() {
        return LOGGER;
    }
}
