package org.iamshield.services.ui.extend;

import org.iamshield.component.ComponentFactory;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;

import java.util.HashMap;
import java.util.Map;

public interface UiTabProviderFactory<T> extends ComponentFactory<T, UiTabProvider> {
    default T create(IAMShieldSession session, ComponentModel model) {
        return null;
    }

    @Override
    default Map<String, Object> getTypeMetadata() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("path", getPath());
        metadata.put("params", getParams());
        return metadata;
    }

    String getPath();

    Map<String, String> getParams();
}
