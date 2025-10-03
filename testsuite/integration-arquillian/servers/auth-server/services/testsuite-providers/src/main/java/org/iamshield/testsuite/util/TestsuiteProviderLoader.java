/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.iamshield.testsuite.util;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.stream.Collectors;

import org.iamshield.provider.IAMShieldDeploymentInfo;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.ProviderLoader;
import org.iamshield.provider.Spi;

/**
 * Loads additional SPIs from provided IAMShieldDeploymentInfo
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
class TestsuiteProviderLoader implements ProviderLoader {

    private final IAMShieldDeploymentInfo info;

    TestsuiteProviderLoader(IAMShieldDeploymentInfo info) {
        this.info = info;
    }

    @Override
    public List<Spi> loadSpis() {
        return info.getProviders().keySet()
                .stream()
                .map(this::instantiateSpi)
                .collect(Collectors.toList());
    }

    private Spi instantiateSpi(Class<? extends Spi> clazz) {
        try {
            return clazz.getDeclaredConstructor().newInstance();
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public List<ProviderFactory> load(Spi spi) {
        return List.of();
    }
}
