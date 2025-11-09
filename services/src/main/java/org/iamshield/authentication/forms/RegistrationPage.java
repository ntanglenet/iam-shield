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

package org.iamshield.authentication.forms;

import jakarta.ws.rs.core.Response.Status;
import org.iamshield.Config;
import org.iamshield.authentication.FormAuthenticator;
import org.iamshield.authentication.FormAuthenticatorFactory;
import org.iamshield.authentication.FormContext;
import org.iamshield.authentication.actiontoken.inviteorg.InviteOrgActionToken;
import org.iamshield.common.Profile;
import org.iamshield.common.Profile.Feature;
import org.iamshield.common.VerificationException;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.AuthenticationExecutionModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.OrganizationModel;
import org.iamshield.organization.OrganizationProvider;
import org.iamshield.organization.utils.Organizations;
import org.iamshield.provider.ProviderConfigProperty;

import jakarta.ws.rs.core.Response;
import org.iamshield.services.messages.Messages;

import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RegistrationPage implements FormAuthenticator, FormAuthenticatorFactory {

    public static final String FIELD_PASSWORD_CONFIRM = "password-confirm";
    public static final String FIELD_PASSWORD = "password";
    public static final String FIELD_EMAIL = "email";
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_LAST_NAME = "lastName";
    public static final String FIELD_FIRST_NAME = "firstName";
    public static final String FIELD_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String PROVIDER_ID = "registration-page-form";

    @Override
    public Response render(FormContext context, LoginFormsProvider form) {
        if (Profile.isFeatureEnabled(Feature.ORGANIZATION)) {
            try {
                InviteOrgActionToken token = Organizations.parseInvitationToken(context.getHttpRequest());

                if (token != null) {
                    IAMShieldSession session = context.getSession();
                    OrganizationProvider provider = session.getProvider(OrganizationProvider.class);
                    OrganizationModel organization = provider.getById(token.getOrgId());

                    if (organization == null || !organization.isEnabled()) {
                        return form.setError(Messages.EXPIRED_ACTION).createErrorPage(Status.BAD_REQUEST);
                    }

                    form.setAttribute("messageHeader", Messages.REGISTER_ORGANIZATION_MEMBER);
                    form.setAttribute(OrganizationModel.ORGANIZATION_NAME_ATTRIBUTE, organization.getName());
                    form.setAttribute(FIELD_EMAIL, token.getEmail());
                }
            } catch (VerificationException e) {
                return form.setError(Messages.EXPIRED_ACTION).createErrorPage(Status.BAD_REQUEST);
            }
        }

        return form.createRegistration();
    }

    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Registration Page";
    }

    @Override
    public String getHelpText() {
        return "This is the controller for the registration page";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public FormAuthenticator create(IAMShieldSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
