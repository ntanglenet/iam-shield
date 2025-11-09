package org.iamshield.testsuite.authentication;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.saml.ArtifactResolver;
import org.iamshield.protocol.saml.ArtifactResolverFactory;
import org.iamshield.protocol.saml.util.ArtifactBindingUtils;

/**
 * This ArtifactResolver should be used only for testing purposes.
 */
public class CustomTestingSamlArtifactResolverFactory implements ArtifactResolverFactory {

    public  static final byte[] TYPE_CODE = {0, 5};
    public static final CustomTestingSamlArtifactResolver resolver = new CustomTestingSamlArtifactResolver();
    
    @Override
    public ArtifactResolver create(IAMShieldSession session) {
        return resolver;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ArtifactBindingUtils.byteArrayToResolverProviderId(TYPE_CODE);
    }
}
