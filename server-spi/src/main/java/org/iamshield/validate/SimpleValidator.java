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
package org.iamshield.validate;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

/**
 * Convenience interface to ease implementation of small {@link Validator} implementations.
 *
 * {@link SimpleValidator SimpleValidator's} should be implemented as singletons.
 */
public interface SimpleValidator extends Validator, ValidatorFactory {

    @Override
    default Validator create(IAMShieldSession session) {
        return this;
    }

    @Override
    default void init(Config.Scope config) {
        // NOOP
    }

    @Override
    default void postInit(IAMShieldSessionFactory factory) {
        // NOOP
    }

    @Override
    default void close() {
        // NOOP
    }
}
