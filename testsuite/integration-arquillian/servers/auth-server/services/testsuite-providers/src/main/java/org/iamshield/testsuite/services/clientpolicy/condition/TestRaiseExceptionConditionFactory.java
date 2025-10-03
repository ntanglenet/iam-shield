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

package org.iamshield.testsuite.services.clientpolicy.condition;

import java.util.Collections;
import java.util.List;

import org.iamshield.Config;
import org.iamshield.Config.Scope;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.services.clientpolicy.condition.ClientPolicyConditionProvider;
import org.iamshield.services.clientpolicy.condition.CliPolicyConditionProviFactory;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class TestRaiseExceptionConditionFactory implements CliPolicyConditionProviFactory {

    public static final String PROVIDER_ID = "test-raise-exception";

    @Override
    public ClientPolicyConditionProvider create(IAMShieldSession session) {
        return new TestRaiseExceptionCondition(session);
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return true;
    }
}
