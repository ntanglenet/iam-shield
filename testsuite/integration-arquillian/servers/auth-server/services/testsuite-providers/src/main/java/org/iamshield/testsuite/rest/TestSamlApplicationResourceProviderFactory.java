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

package org.iamshield.testsuite.rest;

import org.iamshield.Config.Scope;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.representations.adapters.action.LogoutAction;
import org.iamshield.representations.adapters.action.PushNotBeforeAction;
import org.iamshield.representations.adapters.action.TestAvailabilityAction;
import org.iamshield.services.resource.RealmResourceProvider;
import org.iamshield.services.resource.RealmResourceProviderFactory;

import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class TestSamlApplicationResourceProviderFactory implements RealmResourceProviderFactory {

    private final BlockingQueue<LogoutAction> adminLogoutActions = new LinkedBlockingDeque<>();
    private final BlockingQueue<PushNotBeforeAction> pushNotBeforeActions = new LinkedBlockingDeque<>();
    private final BlockingQueue<TestAvailabilityAction> testAvailabilityActions = new LinkedBlockingDeque<>();

    @Override
    public RealmResourceProvider create(IAMShieldSession session) {
        return new TestSamlApplicationResourceProvider(session, adminLogoutActions, pushNotBeforeActions, testAvailabilityActions);
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
        return "saml-app";
    }
}
