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

package org.iamshield.testsuite.forms;

import org.iamshield.Config;
import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.AuthenticatorFactory;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.provider.ProviderConfigProperty;

import jakarta.ws.rs.core.Response;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ClickThroughAuthenticator implements Authenticator, AuthenticatorFactory {
    public static final String PROVIDER_ID = "testsuite-dummy-click-through";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challenge = context.form().createForm("terms.ftl");
        context.challenge(challenge);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (context.getHttpRequest().getDecodedFormParameters().containsKey("cancel")) {
            authenticate(context);
            return;
        }

        context.success();
    }

   @Override
    public String getDisplayType() {
        return "Testsuite Dummy Click Thru";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Testsuite Dummy authenticator.  User needs to click through the page to continue.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create(IAMShieldSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
