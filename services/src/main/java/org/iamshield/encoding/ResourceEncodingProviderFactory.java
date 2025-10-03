package org.iamshield.encoding;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderFactory;

public interface ResourceEncodingProviderFactory extends ProviderFactory<ResourceEncodingProvider> {

    boolean encodeContentType(String contentType);

    @Override
    default void init(Config.Scope config) {
    }

    @Override
    default void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    default void close() {
    }

}
