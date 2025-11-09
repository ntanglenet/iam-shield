/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.testsuite.account;

import org.iamshield.representations.idm.ClientPoliciesRepresentation;
import org.iamshield.representations.idm.ClientPolicyConditionConfigurationRepresentation;
import org.iamshield.representations.idm.ClientProfilesRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.services.clientpolicy.condition.AnyCliConditionFactory;
import org.iamshield.services.clientpolicy.executor.UseLightweightAccessTokenExecutorFactory;
import org.iamshield.testsuite.util.ClientPoliciesUtil.ClientPoliciesBuilder;
import org.iamshield.testsuite.util.ClientPoliciesUtil.ClientPolicyBuilder;
import org.iamshield.testsuite.util.ClientPoliciesUtil.ClientProfileBuilder;
import org.iamshield.testsuite.util.ClientPoliciesUtil.ClientProfilesBuilder;

/**
 *
 * @author rmartinc
 */
public class AccountRestServiceLightweightTokenTest extends AccountRestServiceTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        super.configureTestRealm(testRealm);

        try {
            // enable lightweight tokens for any client in the realm
            ClientProfilesRepresentation profiles = new ClientProfilesBuilder().addProfile(
                    new ClientProfileBuilder().createProfile("enable lightweight tokens", "Profile Lightweight Tokens")
                            .addExecutor(UseLightweightAccessTokenExecutorFactory.PROVIDER_ID, null).toRepresentation()).toRepresentation();
            ClientPoliciesRepresentation policies = new ClientPoliciesBuilder().addPolicy(
                    new ClientPolicyBuilder().createPolicy("enable lightweight tokens", "Policy Lightweight Tokens", true)
                            .addCondition(AnyCliConditionFactory.PROVIDER_ID, new ClientPolicyConditionConfigurationRepresentation())
                            .addProfile("enable lightweight tokens")
                            .toRepresentation()).toRepresentation();
            testRealm.setParsedClientProfiles(profiles);
            testRealm.setParsedClientPolicies(policies);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
