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

package org.iamshield.storage.client;

import org.iamshield.Config;
import org.iamshield.component.ComponentFactory;
import org.iamshield.component.ComponentModel;
import org.iamshield.component.ComponentValidationException;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface ClientStorageProviderFactory<T extends ClientStorageProvider> extends ComponentFactory<T, ClientStorageProvider> {


    /**
     * called per Keycloak transaction.
     *
     * @param session
     * @param model
     * @return
     */
    T create(IAMShieldSession session, ComponentModel model);

    /**
     * This is the name of the provider and will be showed in the admin console as an option.
     *
     * @return
     */
    @Override
    String getId();

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
    default String getHelpText() {
        return "";
    }

    @Override
    default List<ProviderConfigProperty> getConfigProperties() {
        return Collections.EMPTY_LIST;
    }

    @Override
    default void validateConfiguration(IAMShieldSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {

    }

    /**
     * Called when ClientStorageProviderModel is created.  This allows you to do initialization of any additional configuration
     * you need to add.
     *
     * @param session
     * @param realm
     * @param model
     */
    @Override
    default void onCreate(IAMShieldSession session, RealmModel realm, ComponentModel model) {

    }

    /**
     * configuration properties that are common across all UserStorageProvider implementations
     *
     * @return
     */
    @Override
    default
    List<ProviderConfigProperty> getCommonProviderConfigProperties() {
        return ClientStorageProviderSpi.commonConfig();
    }

    @Override
    default
    Map<String, Object> getTypeMetadata() {
        Map<String, Object> metadata = new HashMap<>();
        return metadata;
    }
}
