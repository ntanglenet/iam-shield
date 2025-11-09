package org.iamshield.quarkus.runtime.themes;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.quarkus.runtime.Environment;
import org.iamshield.theme.FolderThemeProvider;
import org.iamshield.theme.ThemeProvider;
import org.iamshield.theme.ThemeProviderFactory;

import java.io.File;
import java.util.Objects;

public class QuarkusFolderThemeProviderFactory implements ThemeProviderFactory {

    private static final String CONFIG_DIR_KEY = "dir";
    private FolderThemeProvider themeProvider;

    @Override
    public ThemeProvider create(IAMShieldSession sessions) {
        return themeProvider;
    }

    @Override
    public void init(Config.Scope config) {
        String configDir = config.get(CONFIG_DIR_KEY);
        File rootDir = getThemeRootDirWithFallback(configDir);
        themeProvider = new FolderThemeProvider(rootDir);
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "folder";
    }

    /**
     * Determines if the theme root directory we get
     * from {@link Config} exists.
     * If not, uses the default theme directory as a fallback.
     *
     * @param rootDirFromConfig string value from {@link Config}
     * @return Directory to use as theme root directory in {@link File} format, either from config or from default. Null if none is available.
     * @throws RuntimeException when filesystem path is not accessible
     */
    private File getThemeRootDirWithFallback(String rootDirFromConfig) {
        File themeRootDir;

        themeRootDir = new File(Objects.requireNonNullElseGet(rootDirFromConfig, Environment::getDefaultThemeRootDir));

        if (!themeRootDir.exists()) {
            return null;
        }

        return themeRootDir;
    }
}
