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
package org.iamshield.broker.provider;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Pedro Igor
 */
public abstract class AbstractIdentityProviderFactory<T extends IdentityProvider> implements IdentityProviderFactory<T> {

    @Override
    public void close() {

    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public T create(IAMShieldSession session) {
        return null;
    }

    @Override
    public Map<String, String> parseConfig(IAMShieldSession session, String config) {
        return new HashMap<>();
    }
}
