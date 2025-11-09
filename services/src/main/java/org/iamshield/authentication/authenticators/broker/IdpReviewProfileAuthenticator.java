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

package org.iamshield.authentication.authenticators.broker;

import org.jboss.logging.Logger;
import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.iamshield.broker.provider.AbstractIdentityProvider;
import org.iamshield.broker.provider.BrokeredIdentityContext;
import org.iamshield.events.Details;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.forms.login.LoginFormsProvider;
import org.iamshield.models.AuthenticatorConfigModel;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.FormMessage;
import org.iamshield.models.utils.UserModelDelegate;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.services.validation.Validation;
import org.iamshield.userprofile.UserProfileContext;
import org.iamshield.userprofile.ValidationException;
import org.iamshield.userprofile.UserProfile;
import org.iamshield.userprofile.UserProfileProvider;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class IdpReviewProfileAuthenticator extends AbstractIdpAuthenticator {

    private static final Logger logger = Logger.getLogger(IdpReviewProfileAuthenticator.class);

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext userCtx, BrokeredIdentityContext brokerContext) {
        IdentityProviderModel idpConfig = brokerContext.getIdpConfig();

        if (requiresUpdateProfilePage(context, userCtx, brokerContext)) {

            logger.debugf("Identity provider '%s' requires update profile action for broker user '%s'.", idpConfig.getAlias(), userCtx.getUsername());

            // No formData for first render. The profile is rendered from userCtx
            Response challengeResponse = context.form()
                    .setAttribute(LoginFormsProvider.UPDATE_PROFILE_CONTEXT_ATTR, userCtx)
                    .setFormData(null)
                    .createUpdateProfilePage();
            context.challenge(challengeResponse);
        } else {
            // Not required to update profile. Marked success
            context.success();
        }
    }

    protected boolean requiresUpdateProfilePage(AuthenticationFlowContext context, SerializedBrokeredIdentityContext userCtx, BrokeredIdentityContext brokerContext) {
        String enforceUpdateProfile = context.getAuthenticationSession().getAuthNote(ENFORCE_UPDATE_PROFILE);
        if (Boolean.parseBoolean(enforceUpdateProfile)) {
            return true;
        }

        String updateProfileFirstLogin;
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null || !authenticatorConfig.getConfig().containsKey(IdpReviewProfileAuthenticatorFactory.UPDATE_PROFILE_ON_FIRST_LOGIN)) {
            updateProfileFirstLogin = IdentityProviderRepresentation.UPFLM_MISSING;
        } else {
            updateProfileFirstLogin = authenticatorConfig.getConfig().get(IdpReviewProfileAuthenticatorFactory.UPDATE_PROFILE_ON_FIRST_LOGIN);
        }

        if(IdentityProviderRepresentation.UPFLM_MISSING.equals(updateProfileFirstLogin)) {
            try {
                UserProfileProvider profileProvider = context.getSession().getProvider(UserProfileProvider.class);
                profileProvider.create(UserProfileContext.IDP_REVIEW, userCtx.getAttributes()).validate();
                return false;
            } catch (ValidationException pve) {
                return true;
            }
        } else {
            return IdentityProviderRepresentation.UPFLM_ON.equals(updateProfileFirstLogin);
        }
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext userCtx, BrokeredIdentityContext brokerContext) {
        EventBuilder event = context.getEvent();
        event.event(EventType.UPDATE_PROFILE).detail(Details.CONTEXT, UserProfileContext.IDP_REVIEW.name());
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        UserModelDelegate updatedProfile = new UserModelDelegate(null) {

            @Override
            public String getId() {
                return userCtx.getId();
            }

            @Override
            public Map<String, List<String>> getAttributes() {
                return userCtx.getAttributes();
            }

            @Override
            public Stream<String> getAttributeStream(String name) {
                return userCtx.getAttribute(name).stream();
            }

            @Override
            public void setAttribute(String name, List<String> values) {
                userCtx.setAttribute(name, values);
            }

            @Override
            public void removeAttribute(String name) {
                userCtx.getAttributes().remove(name);
            }

            @Override
            public String getFirstAttribute(String name) {
                return userCtx.getFirstAttribute(name);
            }

            @Override
            public String getFirstName() {
                return userCtx.getFirstName();
            }

            @Override
            public void setFirstName(String firstName) {
                userCtx.setFirstName(firstName);
            }

            @Override
            public String getEmail() {
                return userCtx.getEmail();
            }

            @Override
            public void setEmail(String email) {
                userCtx.setEmail(email);
            }

            @Override
            public String getLastName() {
                return userCtx.getLastName();
            }

            @Override
            public void setLastName(String lastName) {
                userCtx.setLastName(lastName);
            }

            @Override
            public String getUsername() {
                return userCtx.getUsername();
            }

            @Override
            public void setUsername(String username) {
                userCtx.setUsername(username);
            }

            @Override
            public String getServiceAccountClientLink() {
                return null;
            }

            @Override
            public String getFederationLink() {
                return null;
            }
        };

        UserProfileProvider profileProvider = context.getSession().getProvider(UserProfileProvider.class);
        Map<String, List<String>> attributes = new HashMap<>(formData);
        attributes.putIfAbsent(UserModel.USERNAME, Collections.singletonList(updatedProfile.getUsername()));
        UserProfile profile = profileProvider.create(UserProfileContext.IDP_REVIEW, attributes, updatedProfile);

        try {
            profile.update((attributeName, userModel, oldValue) -> {
                if (attributeName.equals(UserModel.USERNAME)) {
                    context.getAuthenticationSession().setAuthNote(AbstractIdentityProvider.UPDATE_PROFILE_USERNAME_CHANGED, "true");
                    event.clone().event(EventType.UPDATE_PROFILE)
                            .detail(Details.CONTEXT, UserProfileContext.IDP_REVIEW.name())
                            .detail(Details.PREF_PREVIOUS + UserModel.USERNAME, oldValue)
                            .detail(Details.PREF_UPDATED + UserModel.USERNAME, profile.getAttributes().getFirst(UserModel.USERNAME))
                            .success();
                } else if (attributeName.equals(UserModel.EMAIL)) {
                    context.getAuthenticationSession().setAuthNote(AbstractIdentityProvider.UPDATE_PROFILE_EMAIL_CHANGED, "true");
                    event.clone().event(EventType.UPDATE_EMAIL)
                            .detail(Details.CONTEXT, UserProfileContext.IDP_REVIEW.name())
                            .detail(Details.PREVIOUS_EMAIL, oldValue)
                            .detail(Details.UPDATED_EMAIL, profile.getAttributes().getFirst(UserModel.EMAIL))
                            .success();
                }
            });
        } catch (ValidationException pve) {
            List<FormMessage> errors = Validation.getFormErrorsFromValidation(pve.getErrors());

            Response challenge = context.form()
                    .setErrors(errors)
                    .setAttribute(LoginFormsProvider.UPDATE_PROFILE_CONTEXT_ATTR, userCtx)
                    .setFormData(formData)
                    .createUpdateProfilePage();

            context.challenge(challenge);

            return;
        }

        userCtx.saveToAuthenticationSession(context.getAuthenticationSession(), BROKERED_CONTEXT_NOTE);

        logger.debugf("Profile updated successfully after first authentication with identity provider '%s' for broker user '%s'.", brokerContext.getIdpConfig().getAlias(), userCtx.getUsername());

        String newEmail = profile.getAttributes().getFirst(UserModel.EMAIL);

        event.detail(Details.UPDATED_EMAIL, newEmail);

        // Ensure page is always shown when user later returns to it - for example with form "back" button
        context.getAuthenticationSession().setAuthNote(ENFORCE_UPDATE_PROFILE, "true");

        context.success();
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return true;
    }

}
