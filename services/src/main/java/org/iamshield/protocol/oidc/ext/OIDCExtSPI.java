package org.iamshield.protocol.oidc.ext;

import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.Spi;

public class OIDCExtSPI implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "openid-connect-ext";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return OIDCExtProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return OIDCExtProviderFactory.class;
    }

}
