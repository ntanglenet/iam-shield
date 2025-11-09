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
import java.util.stream.Collectors;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.iamshield.authentication.InitiatedActionSupport;
import org.iamshield.authentication.RequiredActionContext;
import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.events.Details;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserModel;
import org.iamshield.models.utils.FormMessage;
import org.iamshield.services.validation.Validation;
import org.iamshield.userprofile.UserProfile;
import org.iamshield.userprofile.UserProfileContext;
import org.iamshield.userprofile.UserProfileProvider;
import org.iamshield.userprofile.ValidationException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class VerifyUserProfile extends UpdateProfile {

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.NOT_SUPPORTED;
    }
    
    @Override
    protected UserModel.RequiredAction getResponseAction(){
        return UserModel.RequiredAction.VERIFY_PROFILE;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        UserModel user = context.getUser();
        UserProfileProvider provider = context.getSession().getProvider(UserProfileProvider.class);
        UserProfile profile = provider.create(UserProfileContext.UPDATE_PROFILE, user);

        try {
            profile.validate();
            context.getAuthenticationSession().removeRequiredAction(getId());
            user.removeRequiredAction(getId());
        } catch (ValidationException e) {
            context.getAuthenticationSession().addRequiredAction(getId());
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        UserProfileProvider provider = context.getSession().getProvider(UserProfileProvider.class);
        UserProfile profile = provider.create(UserProfileContext.UPDATE_PROFILE, context.getUser());
        
        try {
            profile.validate();
            context.success();
        } catch (ValidationException ve) {
            List<FormMessage> errors = Validation.getFormErrorsFromValidation(ve.getErrors());
            MultivaluedMap<String, String> parameters;

            if (context.getHttpRequest().getHttpMethod().equalsIgnoreCase(HttpMethod.GET)) {
                parameters = new MultivaluedHashMap<>();
            } else {
                parameters = context.getHttpRequest().getDecodedFormParameters();
            }

            context.challenge(createResponse(context, parameters, errors));
            
            EventBuilder event = context.getEvent().clone();
            event.event(EventType.VERIFY_PROFILE);
            event.detail(Details.FIELDS_TO_UPDATE, collectFields(errors));
            event.success();
        }
    }

    private String collectFields(List<FormMessage> errors) {
        return errors.stream().map(FormMessage::getField).distinct().collect(Collectors.joining(","));
    }

    @Override
    public RequiredActionProvider create(IAMShieldSession session) {
        return this;
    }

    @Override
    public String getDisplayText() {
        return "Verify Profile";
    }


    @Override
    public String getId() {
        return UserModel.RequiredAction.VERIFY_PROFILE.name();
    }

}
