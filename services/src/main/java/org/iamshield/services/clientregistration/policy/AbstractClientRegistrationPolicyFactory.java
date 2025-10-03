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

package org.iamshield.services.clientregistration.policy;

import java.util.List;

import org.iamshield.Config;
import org.iamshield.component.ComponentModel;
import org.iamshield.component.ComponentValidationException;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.ProviderConfigProperty;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractClientRegistrationPolicyFactory implements ClientRegistrationPolicyFactory {

    protected IAMShieldSessionFactory sessionFactory;

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        this.sessionFactory = factory;
    }

    @Override
    public void close() {
    }

    @Override
    public void validateConfiguration(IAMShieldSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(IAMShieldSession session) {
        return getConfigProperties();
    }
}
