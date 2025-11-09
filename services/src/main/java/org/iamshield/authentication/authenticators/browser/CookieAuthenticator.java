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
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.AuthenticatorUtil;
import org.iamshield.authentication.authenticators.util.AcrStore;
import org.iamshield.authentication.authenticators.util.AuthenticatorUtils;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.organization.protocol.mappers.oidc.OrganizationScope;
import org.iamshield.organization.utils.Organizations;
import org.iamshield.protocol.LoginProtocol;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.messages.Messages;
import org.iamshield.sessions.AuthenticationSessionModel;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CookieAuthenticator implements Authenticator {

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(context.getSession(),
                context.getRealm(), true);
        if (authResult == null) {
            context.attempted();
        } else {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, authSession.getProtocol());
            authSession.setAuthNote(Constants.LOA_MAP, authResult.getSession().getNote(Constants.LOA_MAP));
            context.setUser(authResult.getUser());
            AcrStore acrStore = new AcrStore(context.getSession(), authSession);

            // Cookie re-authentication is skipped if re-authentication is required
            if (protocol.requireReauthentication(authResult.getSession(), authSession)) {
                // Full re-authentication, so we start with no loa
                acrStore.setLevelAuthenticatedToCurrentRequest(Constants.NO_LOA);
                authSession.setAuthNote(AuthenticationManager.FORCED_REAUTHENTICATION, "true");
                context.setForwardedInfoMessage(Messages.REAUTHENTICATE);
                context.attempted();
            } else if(AuthenticatorUtil.isForkedFlow(authSession)){
                context.attempted();
            } else {
                String topLevelFlowId = context.getTopLevelFlow().getId();
                int previouslyAuthenticatedLevel = acrStore.getHighestAuthenticatedLevelFromPreviousAuthentication(topLevelFlowId);
                AuthenticatorUtils.updateCompletedExecutions(context.getAuthenticationSession(), authResult.getSession(), context.getExecution().getId());

                if (acrStore.getRequestedLevelOfAuthentication(context.getTopLevelFlow()) > previouslyAuthenticatedLevel) {
                    // Step-up authentication, we keep the loa from the existing user session.
                    // The cookie alone is not enough and other authentications must follow.
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);

                    if (authSession.getClientNote(Constants.KC_ACTION) != null) {
                        context.setForwardedInfoMessage(Messages.AUTHENTICATE_STRONG);
                    }

                    context.attempted();
                } else {
                    // Cookie only authentication
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);
                    authSession.setAuthNote(AuthenticationManager.SSO_AUTH, "true");
                    context.attachUserSession(authResult.getSession());

                    if (isOrganizationContext(context)) {
                        // if re-authenticating in the scope of an organization, an organization must be resolved prior to authenticating the user
                        context.attempted();
                    } else {
                        context.success();
                    }
                }
            }
        }

    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }

    private boolean isOrganizationContext(AuthenticationFlowContext context) {
        IAMShieldSession session = context.getSession();

        if (Organizations.isEnabledAndOrganizationsPresent(session)) {
            return OrganizationScope.valueOfScope(session) != null;
        }

        return false;
    }
}
