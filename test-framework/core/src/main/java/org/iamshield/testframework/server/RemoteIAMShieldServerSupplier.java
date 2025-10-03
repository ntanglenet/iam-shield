package org.iamshield.testframework.server;

import org.jboss.logging.Logger;

public class RemoteIAMShieldServerSupplier extends AbstractIAMShieldServerSupplier {

    private static final Logger LOGGER = Logger.getLogger(RemoteIAMShieldServerSupplier.class);

    @Override
    public IAMShieldServer getServer() {
        return new RemoteIAMShieldServer();
    }

    @Override
    public boolean requiresDatabase() {
        return false;
    }

    @Override
    public String getAlias() {
        return "remote";
    }

    @Override
    public Logger getLogger() {
        return LOGGER;
    }
}
