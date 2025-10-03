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
package org.iamshield.authentication.actiontoken.inviteorg;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.iamshield.TokenVerifier.Predicate;
import org.iamshield.authentication.AuthenticationProcessor;
import org.iamshield.authentication.actiontoken.AbstractActionTokenHandler;
import org.iamshield.authentication.actiontoken.ActionTokenContext;
import org.iamshield.authentication.actiontoken.TokenUtils;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.OrganizationModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.organization.OrganizationProvider;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.services.Urls;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.messages.Messages;
import org.iamshield.sessions.AuthenticationSessionCompoundId;
import org.iamshield.sessions.AuthenticationSessionModel;

import java.net.URI;
import java.util.Objects;

/**
 * Action token handler for handling invitation of an existing user to an organization. A new user is handled in registration {@link org.iamshield.services.resources.LoginActionsService}.
 */
public class InviteOrgActionTokenHandler extends AbstractActionTokenHandler<InviteOrgActionToken> {

    public InviteOrgActionTokenHandler() {
        super(
          InviteOrgActionToken.TOKEN_TYPE,
          InviteOrgActionToken.class,
          Messages.STALE_INVITE_ORG_LINK,
          EventType.INVITE_ORG,
          Errors.INVALID_TOKEN
        );
    }

    @Override
    public Predicate<? super InviteOrgActionToken>[] getVerifiers(ActionTokenContext<InviteOrgActionToken> tokenContext) {
        return TokenUtils.predicates(
          TokenUtils.checkThat(
            t -> Objects.equals(t.getEmail(), tokenContext.getAuthenticationSession().getAuthenticatedUser().getEmail()),
            Errors.INVALID_EMAIL, getDefaultErrorMessage()
          )
        );
    }

    @Override
    public Response preHandleToken(InviteOrgActionToken token, ActionTokenContext<InviteOrgActionToken> tokenContext) {
        IAMShieldSession session = tokenContext.getSession();
        OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();

        OrganizationModel organization = orgProvider.getById(token.getOrgId());

        if (organization == null) {
            return session.getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setInfo(Messages.ORG_NOT_FOUND, token.getOrgId())
                    .createInfoPage();
        }

        session.getContext().setOrganization(organization);

        return super.preHandleToken(token, tokenContext);
    }

    @Override
    public Response handleToken(InviteOrgActionToken token, ActionTokenContext<InviteOrgActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
        IAMShieldSession session = tokenContext.getSession();
        OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        EventBuilder event = tokenContext.getEvent();

        event.event(EventType.INVITE_ORG).detail(Details.USERNAME, user.getUsername());

        OrganizationModel organization = orgProvider.getById(token.getOrgId());

        if (organization == null) {
            event.user(user).error(Errors.ORG_NOT_FOUND);
            return session.getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setInfo(Messages.ORG_NOT_FOUND, token.getOrgId())
                    .createInfoPage();
        }

        if (organization.isMember(user)) {
            event.user(user).error(Errors.USER_ORG_MEMBER_ALREADY);
            return session.getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setInfo(Messages.ORG_MEMBER_ALREADY, user.getUsername())
                    .setAttribute("pageRedirectUri", organization.getRedirectUrl())
                    .createInfoPage();
        }

        final UriInfo uriInfo = tokenContext.getUriInfo();
        final RealmModel realm = tokenContext.getRealm();

        if (tokenContext.isAuthenticationSessionFresh()) {
            // Update the authentication session in the token
            String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
            token.setCompoundAuthenticationSessionId(authSessionEncodedId);
            UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
                    authSession.getClient().getClientId(), authSession.getTabId(), AuthenticationProcessor.getClientData(session, authSession));
            String confirmUri = builder.build(realm.getName()).toString();

            return session.getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setSuccess(Messages.CONFIRM_ORGANIZATION_MEMBERSHIP, organization.getName())
                    .setAttribute("messageHeader", Messages.CONFIRM_ORGANIZATION_MEMBERSHIP_TITLE)
                    .setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, confirmUri)
                    .setAttribute(OrganizationModel.ORGANIZATION_NAME_ATTRIBUTE, organization.getName())
                    .createInfoPage();
        }

        // if we made it this far then go ahead and add the user to the organization
        orgProvider.addMember(orgProvider.getById(token.getOrgId()), user);

        String redirectUri = token.getRedirectUri();

        if (redirectUri != null) {
            authSession.setAuthNote(AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
            authSession.setRedirectUri(redirectUri);
            authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
        }

        event.success();

        tokenContext.setEvent(event.clone().removeDetail(Details.EMAIL).event(EventType.LOGIN));

        String nextAction = AuthenticationManager.nextRequiredAction(session, authSession, tokenContext.getRequest(), event);

        if (nextAction == null) {
            // do not show account updated page
            authSession.removeAuthNote(AuthenticationManager.END_AFTER_REQUIRED_ACTIONS);

            if (redirectUri != null) {
                // always redirect to the expected URI if provided
                return Response.status(Status.FOUND).location(URI.create(redirectUri)).build();
            }
        }

        return AuthenticationManager.redirectToRequiredActions(session, realm, authSession, uriInfo, nextAction);
    }
}
