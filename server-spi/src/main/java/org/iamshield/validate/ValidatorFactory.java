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

import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.ProviderFactory;

/**
 * A factory for custom {@link Validator} implementations plugged-in through this SPI.
 */
public interface ValidatorFactory extends ProviderFactory<Validator> {

    /**
     * Validates the given validation config.
     * <p>
     * Implementations can use the {@link IAMShieldSession} to validate the given {@link ValidatorConfig}.
     *
     * @param session the {@link IAMShieldSession}
     * @param config  the config to be validated
     * @return the validation result
     */
    default ValidationResult validateConfig(IAMShieldSession session, ValidatorConfig config) {
        return ValidationResult.OK;
    }

    /**
     * This is called when the server shuts down.
     */
    @Override
    default void close() {
        // NOOP
    }
}
