package org.iamshield.vault;

import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

import java.lang.invoke.MethodHandles;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Creates and configures {@link FilesPlainTextVaultProvider}.
 *
 * @author Sebastian Łaskawiec
 */
public class FilesPlainTextVaultProviderFactory extends AbstractVaultProviderFactory {

    private static final Logger logger = Logger.getLogger(MethodHandles.lookup().lookupClass());

    public static final String PROVIDER_ID = "files-plaintext";

    private String vaultDirectory;
    private Path vaultPath;

    @Override
    public VaultProvider create(IAMShieldSession session) {
        if (vaultDirectory == null) {
            logger.debug("Can not create a vault since it's not initialized correctly");
            return null;
        }
        return new FilesPlainTextVaultProvider(vaultPath, getRealmName(session), super.keyResolvers);
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);

        vaultDirectory = config.get("dir");
        if (vaultDirectory == null) {
            logger.debug("PlainTextVaultProviderFactory not configured");
            return;
        }

        vaultPath = Paths.get(vaultDirectory);
        if (!Files.exists(vaultPath)) {
            throw new VaultNotFoundException("The " + vaultPath.toAbsolutePath().toString() + " directory doesn't exist");
        }
        logger.debugf("Configured PlainTextVaultProviderFactory with directory %s", vaultPath.toString());
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
