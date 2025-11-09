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

package org.iamshield.authentication.authenticators.directgrant;

import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.AuthenticationFlowError;
import org.iamshield.authentication.CredentialValidator;
import org.iamshield.credential.CredentialProvider;
import org.iamshield.credential.OTPCredentialProvider;
import org.iamshield.events.Errors;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserCredentialModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.OTPCredentialModel;
import org.iamshield.provider.ProviderConfigProperty;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ValidateOTP extends AbstractDirectGrantAuthenticator implements CredentialValidator<OTPCredentialProvider> {

    public static final String PROVIDER_ID = "direct-grant-validate-otp";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!configuredFor(context.getSession(), context.getRealm(), context.getUser())) {
            if (context.getExecution().isConditional()) {
                context.attempted();
            } else if (context.getExecution().isRequired()) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            }
            return;
        }
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        String otp = inputData.getFirst("otp");

        // KEYCLOAK-12908 Backwards compatibility. If paramter "otp" is null, then assign "totp".
        otp = (otp == null) ? inputData.getFirst("totp") : otp;

        // Always use default OTP credential in case of direct grant authentication
        String credentialId = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser()).getId();

        if (otp == null) {
            if (context.getUser() != null) {
                context.getEvent().user(context.getUser());
            }
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        boolean valid = getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), new UserCredentialModel(credentialId, OTPCredentialModel.TYPE, otp));
        if (!valid) {
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return getCredentialProvider(session).isConfiguredFor(realm, user);
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public String getDisplayType() {
        return "OTP";
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
    public String getHelpText() {
        return "Validates the one time password supplied as a 'totp' form parameter in direct grant request";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new LinkedList<>();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    public OTPCredentialProvider getCredentialProvider(IAMShieldSession session) {
        return (OTPCredentialProvider)session.getProvider(CredentialProvider.class, "keycloak-otp");
    }

}
