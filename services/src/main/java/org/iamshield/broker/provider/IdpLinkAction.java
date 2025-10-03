/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.broker.provider;

import java.io.IOException;
import java.util.Collections;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.authentication.InitiatedActionSupport;
import org.iamshield.authentication.RequiredActionContext;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.AccountRoles;
import org.iamshield.models.ClientModel;
import org.iamshield.models.Constants;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.FormMessage;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.managers.ClientSessionCode;
import org.iamshield.services.resources.IdentityBrokerService;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.util.JsonSerialization;

import static org.iamshield.services.resources.IdentityBrokerService.LINKING_IDENTITY_PROVIDER;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class IdpLinkAction implements RequiredActionProvider, RequiredActionFactory {

    protected static final Logger logger = Logger.getLogger(IdpLinkAction.class);

    public static final String PROVIDER_ID = "idp_link";

    // Authentication session note indicating that client-initiated account linking was triggered from this action
    public static final String KC_ACTION_LINKING_IDENTITY_PROVIDER = "kc_action_linking_identity_provider";

    // Authentication session notes with the status of IDP linking and with the error from IDP linking (idp_link_error filled just in case that status is "error")
    public static final String IDP_LINK_STATUS = "idp_link_status";
    public static final String IDP_LINK_ERROR = "idp_link_error";

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
    public void requiredActionChallenge(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        IAMShieldSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        ClientModel client = authSession.getClient();
        EventBuilder event = context.getEvent().clone();
        event.event(EventType.FEDERATED_IDENTITY_LINK);

        String identityProviderAlias = authSession.getClientNote(Constants.KC_ACTION_PARAMETER);
        if (identityProviderAlias == null) {
            event.error(Errors.UNKNOWN_IDENTITY_PROVIDER);
            context.ignore();
            return;
        }
        event.detail(Details.IDENTITY_PROVIDER, identityProviderAlias);
        IdentityProviderModel identityProviderModel = session.identityProviders().getByAlias(identityProviderAlias);
        if (identityProviderModel == null) {
            event.error(Errors.UNKNOWN_IDENTITY_PROVIDER);
            context.ignore();
            return;
        }

        // Check role
        ClientModel accountService = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        RoleModel manageAccountRole = accountService.getRole(AccountRoles.MANAGE_ACCOUNT);
        if (!user.hasRole(manageAccountRole) || !client.hasScope(manageAccountRole)) {
            RoleModel linkRole = accountService.getRole(AccountRoles.MANAGE_ACCOUNT_LINKS);
            if (!user.hasRole(linkRole) || !client.hasScope(linkRole)) {
                event.error(Errors.NOT_ALLOWED);
                context.ignore();
                return;
            }
        }

        String idpDisplayName = IAMShieldModelUtils.getIdentityProviderDisplayName(session, identityProviderModel);
        Response challenge = context.form()
                .setAttribute("idpDisplayName", idpDisplayName)
                .createForm("link-idp-action.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        IAMShieldSession session = context.getSession();
        RealmModel realm = context.getRealm();
        ClientModel client = authSession.getClient();

        if (!Boolean.parseBoolean(authSession.getAuthNote(IdpLinkAction.KC_ACTION_LINKING_IDENTITY_PROVIDER))) {
            // User confirmed IDP linking. We can redirect to IDP
            String identityProviderAlias = authSession.getClientNote(Constants.KC_ACTION_PARAMETER);

            ClientSessionCode<AuthenticationSessionModel> clientSessionCode = new ClientSessionCode<>(session, realm, authSession);
            clientSessionCode.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
            String noteValue = authSession.getParentSession().getId() + client.getClientId() + identityProviderAlias;
            authSession.setAuthNote(LINKING_IDENTITY_PROVIDER, noteValue);
            authSession.setAuthNote(KC_ACTION_LINKING_IDENTITY_PROVIDER, "true");

            IdentityBrokerService brokerService = new IdentityBrokerService(session);
            Response response = brokerService.performClientInitiatedAccountLogin(identityProviderAlias, clientSessionCode);
            context.challenge(response);
        } else {
            // User already authenticated with IDP
            EventBuilder event = context.getEvent();
            event.event(EventType.FEDERATED_IDENTITY_LINK);

            // Status is supposed to be set by IdentityBrokerService
            String statusNote = authSession.getAuthNote(IdpLinkAction.IDP_LINK_STATUS);
            if (statusNote == null) {
                removeAuthNotes(authSession);
                logger.warn("Not found IDP_LINK_STATUS even if redirect to IDP was already triggered");
                context.failure(Errors.INVALID_REQUEST);
                return;
            }
            RequiredActionContext.KcActionStatus status = RequiredActionContext.KcActionStatus.valueOf(statusNote);
            switch (status) {
                case SUCCESS:
                    context.success();
                    break;
                case CANCELLED:
                    context.cancel();
                    break;
                case ERROR:
                    String error = authSession.getAuthNote(IDP_LINK_ERROR);
                    errorPage(context, error);
                    break;
                default:
                    throw new IllegalStateException("Unknown status in the note idp_link_status: " + status);
            }
            removeAuthNotes(authSession);
        }
    }

    private void removeAuthNotes(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(IdpLinkAction.KC_ACTION_LINKING_IDENTITY_PROVIDER);
        authSession.removeAuthNote(IdpLinkAction.IDP_LINK_STATUS);
        authSession.removeAuthNote(IdpLinkAction.IDP_LINK_ERROR);
    }

    private void errorPage(RequiredActionContext context, String serializedError) {
        FormMessage formMessage;
        try {
            formMessage = JsonSerialization.readValue(serializedError, FormMessage.class);
        } catch (IOException ioe) {
            throw new RuntimeException("Unexpected error when deserialization of error: " + serializedError);
        }
        Response response = context.getSession().getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(context.getAuthenticationSession())
                .setUser(context.getUser())
                .setErrors(Collections.singletonList(formMessage))
                .createErrorPage(Response.Status.BAD_REQUEST);
        context.getEvent().error(formMessage.getMessage());
        context.challenge(response);
    }

    @Override
    public String getDisplayText() {
        return "Linking Identity Provider";
    }

    @Override
    public void close() {

    }
}
