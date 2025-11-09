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

package org.iamshield.authentication.authenticators.browser;

import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.CredentialValidator;
import org.iamshield.credential.CredentialProvider;
import org.iamshield.credential.PasswordCredentialProvider;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.services.messages.Messages;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class PasswordForm extends UsernamePasswordForm implements CredentialValidator<PasswordCredentialProvider> {

    public PasswordForm(IAMShieldSession session) {
        super(session);
    }

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validatePassword(context, context.getUser(), formData, false);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (alreadyAuthenticatedUsingPasswordlessCredential(context)) {
            context.success();
            return;
        }

        // setup webauthn data when passkeys enabled
        if (isConditionalPasskeysEnabled(context.getUser())) {
            webauthnAuth.fillContextForm(context);
        }

        Response challengeResponse = context.form().createLoginPassword();
        context.challenge(challengeResponse);
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().isConfiguredFor(getCredentialProvider(session).getType())
                || (isConditionalPasskeysEnabled(user))
                || alreadyAuthenticatedUsingPasswordlessCredential(session.getContext().getAuthenticationSession());
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginPassword();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return Messages.INVALID_PASSWORD;
    }

    @Override
    public PasswordCredentialProvider getCredentialProvider(IAMShieldSession session) {
        return (PasswordCredentialProvider)session.getProvider(CredentialProvider.class, "keycloak-password");
    }
}
