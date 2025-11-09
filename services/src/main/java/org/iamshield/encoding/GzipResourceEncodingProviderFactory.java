package org.iamshield.encoding;

import org.apache.commons.io.FileUtils;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.common.Version;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.platform.Platform;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class GzipResourceEncodingProviderFactory implements ResourceEncodingProviderFactory {

    private static final Logger logger = Logger.getLogger(GzipResourceEncodingProviderFactory.class);

    private Set<String> excludedContentTypes = new HashSet<>();

    private File cacheDir;

    @Override
    public ResourceEncodingProvider create(IAMShieldSession session) {
        if (cacheDir == null) {
            cacheDir = initCacheDir();
        }

        return new GzipResourceEncodingProvider(cacheDir);
    }

    @Override
    public void init(Config.Scope config) {
        String e = config.get("excludedContentTypes", "image/png image/jpeg");
        excludedContentTypes.addAll(Arrays.asList(e.split(" ")));
    }

    @Override
    public boolean encodeContentType(String contentType) {
        return !excludedContentTypes.contains(contentType);
    }

    @Override
    public String getId() {
        return "gzip";
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("excludedContentTypes")
                .type("string")
                .helpText("A space separated list of content-types to exclude from encoding.")
                .defaultValue("image/png image/jpeg")
                .add()
                .build();
    }

    private synchronized File initCacheDir() {
        if (cacheDir != null) {
            return cacheDir;
        }

        File cacheRoot = new File(Platform.getPlatform().getTmpDirectory(), "kc-gzip-cache");
        File cacheDir = new File(cacheRoot, Version.RESOURCES_VERSION);

        if (cacheRoot.isDirectory()) {
            for (File f : cacheRoot.listFiles()) {
                if (!f.getName().equals(Version.RESOURCES_VERSION)) {
                    try {
                        FileUtils.deleteDirectory(f);
                    } catch (IOException e) {
                        logger.warn("Failed to delete old gzip cache directory", e);
                    }
                }
            }
        }

        if (!cacheDir.isDirectory() && !cacheDir.mkdirs()) {
            logger.warn("Failed to create gzip cache directory");
            return null;
        }

        return cacheDir;
    }
}
