/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.testsuite.federation;

import java.util.List;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.storage.clientscope.ClientScopeStorageProviderFactory;
import org.iamshield.storage.clientscope.ClientScopeStorageProviderModel;

public class HardcodedClientScopeStorageProviderFactory implements ClientScopeStorageProviderFactory<HardcodedClientScopeStorageProvider> {

    public static final String PROVIDER_ID = "hardcoded-clientscope";
    public static final String SCOPE_NAME = "scope_name";
    protected static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    @Override
    public HardcodedClientScopeStorageProvider create(IAMShieldSession session, ComponentModel model) {
        return new HardcodedClientScopeStorageProvider(session, new ClientScopeStorageProviderModel(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
  
    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property().name(SCOPE_NAME)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Hardcoded Scope Name")
                .helpText("Only this scope name is available for lookup")
                .defaultValue("hardcoded-clientscope")
                .add()
                .build();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
