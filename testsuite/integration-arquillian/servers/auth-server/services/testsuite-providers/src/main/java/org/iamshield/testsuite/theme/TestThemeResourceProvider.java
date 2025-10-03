package org.iamshield.testsuite.theme;

import org.iamshield.Config;
import org.iamshield.platform.Platform;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.theme.ClasspathThemeResourceProviderFactory;

public class TestThemeResourceProvider extends ClasspathThemeResourceProviderFactory implements EnvironmentDependentProviderFactory {

    public TestThemeResourceProvider() {
        super("test-resources", TestThemeResourceProvider.class.getClassLoader());
    }

    /**
     * Quarkus detects theme resources automatically, so this provider should only be enabled on Undertow
     *
     * @return true if platform is Undertow
     */
    @Override
    public boolean isSupported(Config.Scope config) {
        return Platform.getPlatform().name().equals("Undertow");
    }
}
