/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.iamshield.authentication.requiredactions;


import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.authentication.CredentialAction;
import org.iamshield.authentication.InitiatedActionSupport;
import org.iamshield.authentication.RequiredActionContext;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.authentication.authenticators.util.AcrStore;
import org.iamshield.authentication.requiredactions.util.CredentialDeleteHelper;
import org.iamshield.credential.CredentialModel;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.OTPCredentialModel;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.utils.StringUtil;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DeleteCredentialAction implements RequiredActionProvider, RequiredActionFactory, CredentialAction {

    public static final String PROVIDER_ID = "delete_credential";

    @Override
    public RequiredActionProvider create(IAMShieldSession session) {
        return this;
    }

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
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


    @Override
    public void evaluateTriggers(RequiredActionContext context) {

    }

    @Override
    public String getCredentialType(IAMShieldSession session, AuthenticationSessionModel authenticationSession) {
        String credentialId = authenticationSession.getClientNote(Constants.KC_ACTION_PARAMETER);
        if (credentialId == null) {
            return null;
        }

        UserModel user = authenticationSession.getAuthenticatedUser();
        if (user == null) {
            return null;
        }

        CredentialModel credential = user.credentialManager().getStoredCredentialById(credentialId);
        if (credential == null) {
            if (credentialId.endsWith("-id")) {
                return credentialId.substring(0, credentialId.length() - 3);
            } else {
                return null;
            }
        } else {
            return credential.getType();
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        String credentialId = context.getAuthenticationSession().getClientNote(Constants.KC_ACTION_PARAMETER);
        UserModel user = context.getUser();
        if (credentialId == null) {
            context.getEvent()
                    .error(Errors.MISSING_CREDENTIAL_ID);
            context.ignore();
            return;
        }

        String credentialLabel;
        CredentialModel credential = user.credentialManager().getStoredCredentialById(credentialId);
        if (credential == null) {
            // Backwards compatibility with account console 1 - When stored credential is not found, it may be federated credential.
            // In this case, it's ID needs to be something like "otp-id", which is returned by account REST GET endpoint as a placeholder
            // for federated credentials (See CredentialHelper.createUserStorageCredentialRepresentation )
            if (credentialId.endsWith("-id")) {
                credentialLabel = credentialId.substring(0, credentialId.length() - 3);
            } else {
                context.getEvent()
                        .detail(Details.CREDENTIAL_ID, credentialId)
                        .error(Errors.CREDENTIAL_NOT_FOUND);
                context.ignore();
                return;
            }
        } else {
            credentialLabel = StringUtil.isNotBlank(credential.getUserLabel()) ? credential.getUserLabel() : credential.getType();
        }

        Response challenge = context.form()
                .setAttribute("credentialLabel", credentialLabel)
                .createForm("delete-credential.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        event.event(EventType.REMOVE_CREDENTIAL);

        EventBuilder deprecatedEvent = null;
        String credentialId = context.getAuthenticationSession().getClientNote(Constants.KC_ACTION_PARAMETER);

        CredentialModel credential = context.getUser().credentialManager().getStoredCredentialById(credentialId);
        if (credential != null) {
            event
                    .detail(Details.CREDENTIAL_TYPE, credential.getType())
                    .detail(Details.CREDENTIAL_ID, credential.getId())
                    .detail(Details.CREDENTIAL_USER_LABEL, credential.getUserLabel());
            if (OTPCredentialModel.TYPE.equals(credential.getType())) {
                deprecatedEvent = event.clone().event(EventType.REMOVE_TOTP);
            }
        }

        try {
            CredentialDeleteHelper.removeCredential(context.getSession(), context.getUser(), credentialId, () -> getCurrentLoa(context.getSession(), context.getAuthenticationSession()));
            context.success();
            if (deprecatedEvent != null) {
                deprecatedEvent.success();
            }

        } catch (WebApplicationException wae) {
            Response response = context.getSession().getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(context.getAuthenticationSession())
                    .setUser(context.getUser())
                    .setError(wae.getMessage())
                    .createErrorPage(Response.Status.BAD_REQUEST);
            event.detail(Details.REASON, wae.getMessage())
                    .error(Errors.DELETE_CREDENTIAL_FAILED);
            if (deprecatedEvent != null) {
                deprecatedEvent.detail(Details.REASON, wae.getMessage())
                        .error(Errors.DELETE_CREDENTIAL_FAILED);
            }
            context.challenge(response);
        }
    }

    private int getCurrentLoa(IAMShieldSession session, AuthenticationSessionModel authSession) {
        return new AcrStore(session, authSession).getLevelOfAuthenticationFromCurrentAuthentication();
    }

    @Override
    public String getDisplayText() {
        return "Delete Credential";
    }

    @Override
    public void close() {

    }
}
