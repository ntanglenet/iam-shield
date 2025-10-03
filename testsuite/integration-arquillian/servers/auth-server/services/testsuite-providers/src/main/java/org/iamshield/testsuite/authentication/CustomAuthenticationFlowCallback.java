/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.testsuite.authentication;

import org.iamshield.authentication.AuthenticationFlowCallback;
import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.AuthenticationFlowError;
import org.iamshield.authentication.AuthenticationFlowException;
import org.iamshield.models.AuthenticationFlowModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

/**
 * @author <a href="mailto:mabartos@redhat.com">Martin Bartos</a>
 */
public class CustomAuthenticationFlowCallback implements AuthenticationFlowCallback {

    public static final String EXPECTED_ERROR_MESSAGE = "Custom Authentication Flow Callback message";

    @Override
    public void onTopFlowSuccess(AuthenticationFlowModel topFlow) {
        throw new AuthenticationFlowException(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, "detail", EXPECTED_ERROR_MESSAGE);
    }

    @Override
    public void onParentFlowSuccess(AuthenticationFlowContext context) {

    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }
}
