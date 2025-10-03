/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.authentication.actiontoken.verifyemail;

import org.iamshield.authentication.AuthenticationProcessor;
import org.iamshield.authentication.actiontoken.AbstractActionTokenHandler;
import org.iamshield.TokenVerifier.Predicate;
import org.iamshield.authentication.actiontoken.*;
import org.iamshield.events.*;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserModel.RequiredAction;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.protocol.oidc.utils.RedirectUtils;
import org.iamshield.services.Urls;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.managers.AuthenticationSessionManager;
import org.iamshield.services.messages.Messages;
import org.iamshield.sessions.AuthenticationSessionCompoundId;
import org.iamshield.sessions.AuthenticationSessionModel;
import java.util.Objects;
import java.util.stream.Stream;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

/**
 * Action token handler for verification of e-mail address.
 * @author hmlnarik
 */
public class VerifyEmailActionTokenHandler extends AbstractActionTokenHandler<VerifyEmailActionToken> {

    public VerifyEmailActionTokenHandler() {
        super(
          VerifyEmailActionToken.TOKEN_TYPE,
          VerifyEmailActionToken.class,
          Messages.STALE_VERIFY_EMAIL_LINK,
          EventType.VERIFY_EMAIL,
          Errors.INVALID_TOKEN
        );
    }

    @Override
    public Predicate<? super VerifyEmailActionToken>[] getVerifiers(ActionTokenContext<VerifyEmailActionToken> tokenContext) {
        return TokenUtils.predicates(
          TokenUtils.checkThat(
            t -> Objects.equals(t.getEmail(), tokenContext.getAuthenticationSession().getAuthenticatedUser().getEmail()),
            Errors.INVALID_EMAIL, getDefaultErrorMessage()
          )
        );
    }

    @Override
    public Response handleToken(VerifyEmailActionToken token, ActionTokenContext<VerifyEmailActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
        IAMShieldSession session = tokenContext.getSession();
        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        EventBuilder event = tokenContext.getEvent();
        LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class);

        event.event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail());

        if (user.isEmailVerified() && !isVerifyEmailActionSet(user, authSession)) {
            event.user(user).error(Errors.EMAIL_ALREADY_VERIFIED);

            return forms
                    .setAuthenticationSession(authSession)
                    .setAttribute("messageHeader", forms.getMessage(Messages.EMAIL_VERIFIED_ALREADY_HEADER, user.getEmail()))
                    .setInfo(Messages.EMAIL_VERIFIED_ALREADY, user.getEmail())
                    .setUser(user)
                    .createInfoPage();
        }

        final UriInfo uriInfo = tokenContext.getUriInfo();
        final RealmModel realm = tokenContext.getRealm();

        if (tokenContext.isAuthenticationSessionFresh()) {
            // Update the authentication session in the token
            token.setCompoundOriginalAuthenticationSessionId(token.getCompoundAuthenticationSessionId());

            String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
            token.setCompoundAuthenticationSessionId(authSessionEncodedId);
            UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
                    authSession.getClient().getClientId(), authSession.getTabId(), AuthenticationProcessor.getClientData(session, authSession));
            String confirmUri = builder.build(realm.getName()).toString();

            return forms
                    .setAuthenticationSession(authSession)
                    .setAttribute("messageHeader", forms.getMessage(Messages.CONFIRM_EMAIL_ADDRESS_VERIFICATION_HEADER, user.getEmail()))
                    .setSuccess(Messages.CONFIRM_EMAIL_ADDRESS_VERIFICATION, user.getEmail())
                    .setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, confirmUri)
                    .setUser(user)
                    .createInfoPage();
        }

        // verify user email as we know it is valid as this entry point would never have gotten here.
        user.setEmailVerified(true);
        user.removeRequiredAction(RequiredAction.VERIFY_EMAIL);
        authSession.removeRequiredAction(RequiredAction.VERIFY_EMAIL);

        String redirectUri = RedirectUtils.verifyRedirectUri(tokenContext.getSession(), token.getRedirectUri(), authSession.getClient());
        if (redirectUri != null) {
            authSession.setAuthNote(AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
            authSession.setRedirectUri(redirectUri);
            authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
        }

        event.success();

        if (token.getCompoundOriginalAuthenticationSessionId() != null) {
            AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
            asm.removeAuthenticationSession(tokenContext.getRealm(), authSession, true);

            return forms
                    .setAuthenticationSession(authSession)
                    .setAttribute("messageHeader", forms.getMessage(Messages.EMAIL_VERIFIED_HEADER, user.getEmail()))
                    .setSuccess(Messages.EMAIL_VERIFIED)
                    .setUser(user)
                    .createInfoPage();
        }

        tokenContext.setEvent(event.clone().removeDetail(Details.EMAIL).event(EventType.LOGIN));

        String nextAction = AuthenticationManager.nextRequiredAction(session, authSession, tokenContext.getRequest(), event);
        return AuthenticationManager.redirectToRequiredActions(session, realm, authSession, uriInfo, nextAction);
    }

    private boolean isVerifyEmailActionSet(UserModel user, AuthenticationSessionModel authSession) {
        return Stream.concat(user.getRequiredActionsStream(), authSession.getRequiredActions().stream())
                .anyMatch(RequiredAction.VERIFY_EMAIL.name()::equals);
    }
}
