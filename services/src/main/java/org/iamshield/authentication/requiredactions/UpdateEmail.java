/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.authentication.requiredactions;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.authentication.AuthenticationProcessor;
import org.iamshield.authentication.AuthenticatorUtil;
import org.iamshield.authentication.InitiatedActionSupport;
import org.iamshield.authentication.RequiredActionContext;
import org.iamshield.authentication.RequiredActionFactory;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.authentication.actiontoken.updateemail.UpdateEmailActionToken;
import org.iamshield.common.Profile;
import org.iamshield.common.util.Time;
import org.iamshield.email.EmailException;
import org.iamshield.email.EmailTemplateProvider;
import org.iamshield.events.Details;
import org.iamshield.events.Errors;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.forms.login.LoginFormsPages;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.forms.login.freemarker.Templates;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RequiredActionConfigModel;
import org.iamshield.models.RequiredActionProviderModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserModel.RequiredAction;
import org.iamshield.models.utils.FormMessage;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.services.Urls;
import org.iamshield.services.validation.Validation;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.userprofile.EventAuditingAttributeChangeListener;
import org.iamshield.userprofile.UserProfile;
import org.iamshield.userprofile.UserProfileContext;
import org.iamshield.userprofile.UserProfileProvider;
import org.iamshield.userprofile.ValidationException;

public class UpdateEmail implements RequiredActionProvider, RequiredActionFactory, EnvironmentDependentProviderFactory {

    private static final Logger logger = Logger.getLogger(UpdateEmail.class);

    public static final String CONFIG_VERIFY_EMAIL = "verifyEmail";
    private static final String FORCE_EMAIL_VERIFICATION = "forceEmailVerification";

    public static boolean isEnabled(RealmModel realm) {
        if (!Profile.isFeatureEnabled(Profile.Feature.UPDATE_EMAIL)) {
            return false;
        }

        RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(RequiredAction.UPDATE_EMAIL.name());

        return model != null && model.isEnabled();
    }

    public static boolean isVerifyEmailEnabled(RealmModel realm) {
        if (!isEnabled(realm)) {
            return false;
        }

        RequiredActionConfigModel config = realm.getRequiredActionConfigByAlias(RequiredAction.UPDATE_EMAIL.name());

        if (config == null) {
            return false;
        }

        return isVerifyEmailEnabled(realm, config);
    }

    public static void forceEmailVerification(IAMShieldSession session) {
        session.setAttribute(FORCE_EMAIL_VERIFICATION, true);
    }

    private static boolean isVerifyEmailEnabled(RealmModel realm, RequiredActionConfigModel config) {
        boolean forceVerifyEmail = Boolean.parseBoolean(config.getConfigValue(CONFIG_VERIFY_EMAIL, Boolean.FALSE.toString()));
        return forceVerifyEmail || realm.isVerifyEmail();
    }

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public String getDisplayText() {
        return "Update Email";
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (isEnabled(context.getRealm())) {
            IAMShieldSession session = context.getSession();

            // skip and clear UPDATE_EMAIL required action if email is readonly
            UserProfileProvider profileProvider = context.getSession().getProvider(UserProfileProvider.class);
            UserProfile profile = profileProvider.create(UserProfileContext.UPDATE_EMAIL, context.getUser());
            if (profile.getAttributes().isReadOnly(UserModel.EMAIL)) {
                context.getUser().removeRequiredAction(UserModel.RequiredAction.UPDATE_EMAIL);
                return;
            }

            if (session.getAttributeOrDefault(FORCE_EMAIL_VERIFICATION, Boolean.FALSE)) {
                sendEmailUpdateConfirmation(context, false);
                return;
            }

            context.challenge(context.form().createResponse(UserModel.RequiredAction.UPDATE_EMAIL));
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        if (!isEnabled(context.getRealm())) {
            return;
        }
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String newEmail = formData.getFirst(UserModel.EMAIL);

        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        UserProfile emailUpdateValidationResult;
        try {
            emailUpdateValidationResult = validateEmailUpdate(context.getSession(), user, newEmail);
        } catch (ValidationException pve) {
            List<FormMessage> errors = Validation.getFormErrorsFromValidation(pve.getErrors());
            context.challenge(context.form().setErrors(errors).setFormData(formData)
                    .createResponse(UserModel.RequiredAction.UPDATE_EMAIL));
            return;
        }

        final boolean logoutSessions = "on".equals(formData.getFirst("logout-sessions"));
        if (!isVerifyEmailEnabled(realm, context.getConfig()) || Validation.isBlank(newEmail)
                || Objects.equals(user.getEmail(), newEmail) && user.isEmailVerified()) {
            if (logoutSessions) {
                AuthenticatorUtil.logoutOtherSessions(context);
            }
            updateEmailWithoutConfirmation(context, emailUpdateValidationResult);
            return;
        }

        sendEmailUpdateConfirmation(context, logoutSessions);
    }

    private void sendEmailUpdateConfirmation(RequiredActionContext context, boolean logoutSessions) {
        UserModel user = context.getUser();
        String oldEmail = user.getEmail();
        String newEmail = context.getHttpRequest().getDecodedFormParameters().getFirst(UserModel.EMAIL);

        RealmModel realm = context.getRealm();
        int validityInSecs = realm.getActionTokenGeneratedByUserLifespan(UpdateEmailActionToken.TOKEN_TYPE);

        UriInfo uriInfo = context.getUriInfo();
        IAMShieldSession session = context.getSession();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

        UpdateEmailActionToken actionToken = new UpdateEmailActionToken(user.getId(), Time.currentTime() + validityInSecs,
                oldEmail, newEmail, authenticationSession.getClient().getClientId(), logoutSessions, authenticationSession.getRedirectUri());

        String link = Urls
                .actionTokenBuilder(uriInfo.getBaseUri(), actionToken.serialize(session, realm, uriInfo),
                        authenticationSession.getClient().getClientId(), authenticationSession.getTabId(), AuthenticationProcessor.getClientData(session, authenticationSession))

                .build(realm.getName()).toString();

        context.getEvent().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, newEmail);
        try {
            session.getProvider(EmailTemplateProvider.class).setAuthenticationSession(authenticationSession).setRealm(realm)
                    .setUser(user).sendEmailUpdateConfirmation(link, TimeUnit.SECONDS.toMinutes(validityInSecs), newEmail);
        } catch (EmailException e) {
            logger.error("Failed to send email for email update", e);
            context.getEvent().error(Errors.EMAIL_SEND_FAILED);
            return;
        }
        context.getEvent().success();

        LoginFormsProvider forms = context.form();
        context.challenge(forms.setAttribute("messageHeader", forms.getMessage("emailUpdateConfirmationSentTitle"))
                .setInfo("emailUpdateConfirmationSent", newEmail).createForm(Templates.getTemplate(LoginFormsPages.INFO)));
    }

    private void updateEmailWithoutConfirmation(RequiredActionContext context,
                                                UserProfile emailUpdateValidationResult) {

        updateEmailNow(context.getEvent(), context.getUser(), emailUpdateValidationResult);
        context.success();
    }

    public static UserProfile validateEmailUpdate(IAMShieldSession session, UserModel user, String newEmail) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle(UserModel.USERNAME, user.getUsername());
        formData.putSingle(UserModel.EMAIL, newEmail);
        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.UPDATE_EMAIL, formData, user);
        profile.validate();
        return profile;
    }

    public static void updateEmailNow(EventBuilder event, UserModel user, UserProfile emailUpdateValidationResult) {

        String oldEmail = user.getEmail();
        String newEmail = emailUpdateValidationResult.getAttributes().getFirst(UserModel.EMAIL);
        event.event(EventType.UPDATE_EMAIL).detail(Details.PREVIOUS_EMAIL, oldEmail).detail(Details.UPDATED_EMAIL, newEmail);
        emailUpdateValidationResult.update(false, new EventAuditingAttributeChangeListener(emailUpdateValidationResult, event));
    }

    @Override
    public RequiredActionProvider create(IAMShieldSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return UserModel.RequiredAction.UPDATE_EMAIL.name();
    }

    @Override
    public int getMaxAuthAge(IAMShieldSession session) {
        // always require re-authentication
        return 0;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("verifyEmail")
                .label("Force Email Verification")
                .helpText("If enabled, the user will be forced to verify the email regardless if email verification is enabled at the realm level or not. Otherwise, verification will be based on the realm level setting.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(Boolean.FALSE)
                .add().build();
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.UPDATE_EMAIL);
    }
}
