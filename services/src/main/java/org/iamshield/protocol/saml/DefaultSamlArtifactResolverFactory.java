package org.iamshield.protocol.saml;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

public class DefaultSamlArtifactResolverFactory implements ArtifactResolverFactory {
    
    /** SAML 2 artifact type code (0x0004). */
    public static final byte[] TYPE_CODE = {0, 4};

    private DefaultSamlArtifactResolver artifactResolver;

    @Override
    public DefaultSamlArtifactResolver create(IAMShieldSession session) {
        return artifactResolver;
    }

    @Override
    public void init(Config.Scope config) {
        // Nothing to initialize
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        artifactResolver = new DefaultSamlArtifactResolver();
    }

    @Override
    public void close() {
        // Nothing to close
    }

    @Override
    public String getId() {
        return "default";
    }

}
