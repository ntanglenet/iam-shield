package org.iamshield.services.ui.extend;

import org.iamshield.component.ComponentFactory;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.ProviderFactory;

public interface UiPageProviderFactory<T> extends ComponentFactory<T, UiPageProvider> {
    default T create(IAMShieldSession session, ComponentModel model) {
        return null;
    }
}
