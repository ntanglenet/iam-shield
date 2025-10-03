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

package org.iamshield.keys;

import org.iamshield.Config;
import org.iamshield.component.ComponentFactory;
import org.iamshield.component.ComponentModel;
import org.iamshield.crypto.KeyUse;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public interface KeyProviderFactory<T extends KeyProvider> extends ComponentFactory<T, KeyProvider> {

    T create(IAMShieldSession session, ComponentModel model);

    default boolean createFallbackKeys(IAMShieldSession session, KeyUse keyUse, String algorithm) {
        return false;
    }

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
