package org.iamshield.testframework.server;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

public class ClusteredIAMShieldServerSupplier extends AbstractIAMShieldServerSupplier {

    private static final Logger LOGGER = Logger.getLogger(ClusteredIAMShieldServerSupplier.class);

    @ConfigProperty(name = "numContainer", defaultValue = "2")
    int numContainers = 2;

    @ConfigProperty(name = "images", defaultValue = ClusteredIAMShieldServer.SNAPSHOT_IMAGE)
    String images = ClusteredIAMShieldServer.SNAPSHOT_IMAGE;

    @Override
    public IAMShieldServer getServer() {
        return new ClusteredIAMShieldServer(numContainers, images);
    }

    @Override
    public boolean requiresDatabase() {
        return true;
    }

    @Override
    public String getAlias() {
        return "cluster";
    }

    @Override
    public Logger getLogger() {
        return LOGGER;
    }
}
