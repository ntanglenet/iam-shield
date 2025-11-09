/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.iamshield.authentication.authenticators.browser;

import java.util.Collections;
import java.util.List;

import jakarta.ws.rs.core.MultivaluedMap;
import org.iamshield.WebAuthnConstants;
import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.iamshield.credential.CredentialProvider;
import org.iamshield.credential.WebAuthnPasswordlessCredentialProvider;
import org.iamshield.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.WebAuthnPolicy;
import org.iamshield.models.credential.WebAuthnCredentialModel;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.utils.StringUtil;

/**
 * Authenticator for WebAuthn authentication with passwordless credential. This class is temporary and will be likely
 * removed in the future during future improvements in authentication SPI
 */
public class WebAuthnPasswordlessAuthenticator extends WebAuthnAuthenticator {

    public WebAuthnPasswordlessAuthenticator(IAMShieldSession session) {
        super(session);
    }

    @Override
    protected WebAuthnPolicy getWebAuthnPolicy(AuthenticationFlowContext context) {
        return context.getRealm().getWebAuthnPolicyPasswordless();
    }

    @Override
    protected String getCredentialType() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    @Override
    protected boolean shouldDisplayAuthenticators(AuthenticationFlowContext context){
        return false;
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {
        // ask the user to do required action to register webauthn authenticator
        AuthenticationSessionModel authenticationSession = session.getContext().getAuthenticationSession();
        if (!authenticationSession.getRequiredActions().contains(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID)) {
            authenticationSession.addRequiredAction(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID);
        }
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(IAMShieldSession session) {
        return Collections.singletonList((WebAuthnPasswordlessRegisterFactory)session.getIAMShieldSessionFactory().getProviderFactory(RequiredActionProvider.class, WebAuthnPasswordlessRegisterFactory.PROVIDER_ID));
    }


    @Override
    public WebAuthnPasswordlessCredentialProvider getCredentialProvider(IAMShieldSession session) {
        return (WebAuthnPasswordlessCredentialProvider)session.getProvider(CredentialProvider.class, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        String username = formData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (StringUtil.isNotBlank(username)) {
            // user entered a username directly, check if user exists
            boolean validUsername = validateUsername(context, formData, username);
            if (!validUsername) {
                context.attempted();
                return;
            }
        } else if (!formData.containsKey(WebAuthnConstants.USER_HANDLE)) {
            // user submitted an empty form without webauthn credential selection
            context.attempted();
            return;
        }

        // user selected a webauthn credential, proceed with webauthn authentication
        super.action(context);
    }

    protected boolean validateUsername(AuthenticationFlowContext context, MultivaluedMap<String, String> formData, String username) {
        return new UsernameForm().validateUser(context, formData);
    }

}
