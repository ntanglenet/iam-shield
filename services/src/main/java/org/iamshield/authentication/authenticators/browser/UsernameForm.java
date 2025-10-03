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

import java.util.Objects;

import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.iamshield.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserModel;
import org.iamshield.services.messages.Messages;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.iamshield.sessions.AuthenticationSessionModel;

public final class UsernameForm extends UsernamePasswordForm {

    public UsernameForm() {
        super();
    }

    public UsernameForm(IAMShieldSession session) {
        super(session);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (context.getUser() != null) {
            // We can skip the form when user is re-authenticating. Unless current user has some IDP set, so he can re-authenticate with that IDP
            if (!this.hasLinkedBrokers(context)) {
                context.success();
                return;
            }
        }
        super.authenticate(context);
    }

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUser(context, formData);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (!formData.isEmpty()) forms.setFormData(formData);

        return forms.createLoginUsername();
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsername();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        if (context.getRealm().isLoginWithEmailAllowed())
            return Messages.INVALID_USERNAME_OR_EMAIL;
        return Messages.INVALID_USERNAME;
    }

    /**
     * Checks if the context user, if it has been set, is currently linked to any IDPs they could use to authenticate.
     * If the auth session has an existing IDP in the brokered context, it is filtered out.
     *
     * @param context a reference to the {@link AuthenticationFlowContext}
     * @return {@code true} if the context user has federated IDPs that can be used for authentication; {@code false} otherwise.
     */
    private boolean hasLinkedBrokers(AuthenticationFlowContext context) {
        IAMShieldSession session = context.getSession();
        UserModel user = context.getUser();
        if (user == null) {
            return false;
        }
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        final IdentityProviderModel existingIdp = (serializedCtx == null) ? null : serializedCtx.deserialize(session, authSession).getIdpConfig();

        return session.users().getFederatedIdentitiesStream(session.getContext().getRealm(), user)
                .map(fedIdentity -> session.identityProviders().getByAlias(fedIdentity.getIdentityProvider()))
                .filter(Objects::nonNull)
                .anyMatch(idpModel -> existingIdp == null || !Objects.equals(existingIdp.getAlias(), idpModel.getAlias()));

    }
}
