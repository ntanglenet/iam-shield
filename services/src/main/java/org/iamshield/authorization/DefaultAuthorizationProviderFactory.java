/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.authorization;

import org.iamshield.Config;
import org.iamshield.authorization.policy.evaluation.DefaultPolicyEvaluator;
import org.iamshield.authorization.policy.evaluation.PolicyEvaluator;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultAuthorizationProviderFactory implements AuthorizationProviderFactory {

    private PolicyEvaluator policyEvaluator = new DefaultPolicyEvaluator();

    @Override
    public AuthorizationProvider create(IAMShieldSession session) {
        return create(session, session.getContext().getRealm());
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "authorization";
    }

    @Override
    public AuthorizationProvider create(IAMShieldSession session, RealmModel realm) {
        return new AuthorizationProvider(session, realm, policyEvaluator);
    }
}
