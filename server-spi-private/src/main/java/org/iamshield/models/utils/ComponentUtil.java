/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.models.utils;

import org.jboss.logging.Logger;
import org.iamshield.component.ComponentFactory;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserProvider;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.representations.idm.ComponentRepresentation;
import org.iamshield.storage.OnCreateComponent;
import org.iamshield.storage.OnUpdateComponent;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ComponentUtil {

    private static final Logger logger = Logger.getLogger(ComponentUtil.class);

    public static Map<String, ProviderConfigProperty> getComponentConfigProperties(IAMShieldSession session, ComponentRepresentation component) {
        return getComponentConfigProperties(session, component.getProviderType(), component.getProviderId());
    }

    public static Map<String, ProviderConfigProperty> getComponentConfigProperties(IAMShieldSession session, ComponentModel component) {
        return getComponentConfigProperties(session, component.getProviderType(), component.getProviderId());
    }

    public static ComponentFactory getComponentFactory(IAMShieldSession session, ComponentRepresentation component) {
        return getComponentFactory(session, component.getProviderType(), component.getProviderId());
    }

    public static ComponentFactory getComponentFactory(IAMShieldSession session, ComponentModel component) {
        return getComponentFactory(session, component.getProviderType(), component.getProviderId());
    }

    public static Map<String, ProviderConfigProperty> getComponentConfigProperties(IAMShieldSession session, String providerType, String providerId) {
        try {
            ComponentFactory componentFactory = getComponentFactory(session, providerType, providerId);
            List<ProviderConfigProperty> l = componentFactory.getConfigProperties();
            Map<String, ProviderConfigProperty> properties = new HashMap<>();
            for (ProviderConfigProperty p : l) {
                properties.put(p.getName(), p);
            }
            List<ProviderConfigProperty> common = componentFactory.getCommonProviderConfigProperties();
            for (ProviderConfigProperty p : common) {
                properties.put(p.getName(), p);
            }

            return properties;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static ComponentFactory getComponentFactory(IAMShieldSession session, String providerType, String providerId) {
        Class<? extends Provider> provider = session.getProviderClass(providerType);
        if (provider == null) {
            throw new IllegalArgumentException("Invalid provider type '" + providerType + "'");
        }

        ProviderFactory<? extends Provider> f = session.getIAMShieldSessionFactory().getProviderFactory(provider, providerId);
        if (f == null) {
            throw new IllegalArgumentException("No such provider '" + providerId + "'");
        }

        ComponentFactory cf = (ComponentFactory) f;
        return cf;
    }

    public static void notifyCreated(IAMShieldSession session, RealmModel realm, ComponentModel model) {
        ComponentFactory factory = getComponentFactory(session, model);
        factory.onCreate(session, realm, model);
        UserProvider users = session.users();
        if (users instanceof OnCreateComponent) {
            ((OnCreateComponent) users).onCreate(session, realm, model);
        }
    }
    public static void notifyUpdated(IAMShieldSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        ComponentFactory factory = getComponentFactory(session, newModel);
        factory.onUpdate(session, realm, oldModel, newModel);
        UserProvider users = session.users();
        if (users instanceof OnUpdateComponent) {
            ((OnUpdateComponent) users).onUpdate(session, realm, oldModel, newModel);
        }
    }
    public static void notifyPreRemove(IAMShieldSession session, RealmModel realm, ComponentModel model) {
        try {
            ComponentFactory factory = getComponentFactory(session, model);
            factory.preRemove(session, realm, model);
        } catch (IllegalArgumentException iae) {
            // We allow to remove broken providers without throwing an exception
            logger.warn(iae.getMessage());
        }
    }

}
