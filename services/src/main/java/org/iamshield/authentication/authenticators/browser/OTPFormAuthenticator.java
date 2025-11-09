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
import org.iamshield.authentication.AuthenticationFlowError;
import org.iamshield.authentication.Authenticator;
import org.iamshield.authentication.CredentialValidator;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.authentication.requiredactions.UpdateTotp;
import org.iamshield.credential.CredentialProvider;
import org.iamshield.credential.OTPCredentialProvider;
import org.iamshield.credential.OTPCredentialProviderFactory;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserCredentialModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.OTPCredentialModel;
import org.iamshield.services.messages.Messages;
import org.iamshield.services.validation.Validation;
import org.iamshield.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class OTPFormAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator, CredentialValidator<OTPCredentialProvider> {

    // Freemarker attribute where selected OTP credential will be stored
    public static final String SELECTED_OTP_CREDENTIAL_ID = "selectedOtpCredentialId";

    // Label to be shown in the UI for the "unnamed" OTP credential, which doesn't have userLabel
    public static final String UNNAMED = "unnamed";


    @Override
    public void action(AuthenticationFlowContext context) {
        validateOTP(context);
    }


    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = challenge(context, null);
        context.challenge(challengeResponse);
    }


    public void validateOTP(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        String otp = inputData.getFirst("otp");

        String credentialId = inputData.getFirst("selectedCredentialId");

        if (credentialId == null || credentialId.isEmpty()) {
            OTPCredentialModel defaultOtpCredential = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser());
            credentialId = defaultOtpCredential==null ? "" : defaultOtpCredential.getId();
        }
        context.getEvent().detail(Details.SELECTED_CREDENTIAL_ID, credentialId);

        context.form().setAttribute(SELECTED_OTP_CREDENTIAL_ID, credentialId);

        UserModel userModel = context.getUser();
        boolean userEnabled = enabledUser(context, userModel);
        // the brute force lock might be lifted/user enabled in the meantime -> we need to clear the auth session note
        if (userEnabled) {
            context.getAuthenticationSession().removeAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID);
        }
        if("true".equals(context.getAuthenticationSession().getAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID))) {
            context.getEvent().user(context.getUser()).error(Errors.INVALID_AUTHENTICATION_SESSION);
            // challenge already set by calling enabledUser() above
            return;
        }
        if (!userEnabled) {
            // error in context is set in enabledUser/isDisabledByBruteForce
            context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID, "true");
            return;
        }

        if (otp == null) {
            Response challengeResponse = challenge(context,null);
            context.challenge(challengeResponse);
            return;
        }
        boolean valid = context.getUser().credentialManager().isValid(new UserCredentialModel(credentialId, getCredentialProvider(context.getSession()).getType(), otp));
        if (!valid) {
            context.getEvent().user(userModel)
                    .error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = challenge(context, Messages.INVALID_TOTP, Validation.FIELD_OTP_CODE);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return;
        }
        context.success(OTPCredentialModel.TYPE);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    protected String disabledByBruteForceError(String error) {
        if(Errors.USER_TEMPORARILY_DISABLED.equals(error)) {
            return Messages.ACCOUNT_TEMPORARILY_DISABLED_TOTP;
        }
        return Messages.ACCOUNT_PERMANENTLY_DISABLED_TOTP;
    }

    @Override
    protected String disabledByBruteForceFieldError() {
        return Validation.FIELD_OTP_CODE;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginTotp();
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().isConfiguredFor(getCredentialProvider(session).getType());
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {
        AuthenticationSessionModel authenticationSession = session.getContext().getAuthenticationSession();
        if (!authenticationSession.getRequiredActions().contains(UserModel.RequiredAction.CONFIGURE_TOTP.name())) {
            authenticationSession.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    public List<RequiredActionFactory> getRequiredActions(IAMShieldSession session) {
        return Collections.singletonList((UpdateTotp)session.getIAMShieldSessionFactory().getProviderFactory(RequiredActionProvider.class, UserModel.RequiredAction.CONFIGURE_TOTP.name()));
    }

    @Override
    public void close() {

    }

    @Override
    public OTPCredentialProvider getCredentialProvider(IAMShieldSession session) {
        return (OTPCredentialProvider)session.getProvider(CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID);
    }

}
