package org.iamshield.protocol.oidc.ext;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderFactory;

public interface OIDCExtProviderFactory extends ProviderFactory<OIDCExtProvider> {

    @Override
    default void init(Config.Scope config) {

    }

    @Override
    default void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    default void close() {

    }

    @Override
    default int order() {
        return 0;
    }

}
