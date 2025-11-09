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

package org.iamshield.policy;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.PasswordPolicy;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DefaultPasswordPolicyManagerProvider implements PasswordPolicyManagerProvider {

    private IAMShieldSession session;

    public DefaultPasswordPolicyManagerProvider(IAMShieldSession session) {
        this.session = session;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        for (PasswordPolicyProvider p : getProviders(realm, session)) {
            PolicyError policyError = p.validate(realm, user, password);
            if (policyError != null) {
                return policyError;
            }
        }
        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        for (PasswordPolicyProvider p : getProviders(session)) {
            PolicyError policyError = p.validate(user, password);
            if (policyError != null) {
                return policyError;
            }
        }
        return null;
    }

    @Override
    public void close() {
    }

    private List<PasswordPolicyProvider> getProviders(IAMShieldSession session) {
        return getProviders(session.getContext().getRealm(), session);

    }

    private List<PasswordPolicyProvider> getProviders(RealmModel realm, IAMShieldSession session) {
        LinkedList<PasswordPolicyProvider> list = new LinkedList<>();
        PasswordPolicy policy = realm.getPasswordPolicy();
        for (String id : policy.getPolicies()) {
            PasswordPolicyProvider provider = session.getProvider(PasswordPolicyProvider.class, id);
            list.add(provider);
        }
        return list;
    }

}
