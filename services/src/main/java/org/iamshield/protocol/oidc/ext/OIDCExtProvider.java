package org.iamshield.protocol.oidc.ext;

import org.iamshield.events.EventBuilder;
import org.iamshield.provider.Provider;

public interface OIDCExtProvider extends Provider {

    void setEvent(EventBuilder event);

    @Override
    default void close() {
    }

}
