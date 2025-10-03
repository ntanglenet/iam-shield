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
package org.iamshield.forms.login.freemarker.model;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import jakarta.ws.rs.core.MultivaluedMap;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserModel;
import org.iamshield.userprofile.UserProfile;
import org.iamshield.userprofile.UserProfileContext;
import org.iamshield.userprofile.UserProfileProvider;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author Vlastimil Elias <velias@redhat.com>
 */
public class RegisterBean extends AbstractUserProfileBean {

    private Map<String, String> formDataLegacy = new HashMap<>();

    public RegisterBean(MultivaluedMap<String, String> formData, IAMShieldSession session) {
        
        super(formData);
        init(session, true);
        
        if (formData != null) {
            for (String k : formData.keySet()) {
                this.formDataLegacy.put(k, formData.getFirst(k));
            }
        }
    }

    @Override
    protected UserProfile createUserProfile(UserProfileProvider provider) {
        return provider.create(UserProfileContext.REGISTRATION, null, (UserModel) null);
    }

    @Override
    protected Stream<String> getAttributeDefaultValues(String name) {
        return null;
    }
    
    @Override 
    public String getContext() {
        return UserProfileContext.REGISTRATION.name();
    }
    
    public Map<String, String> getFormData() {
        return formDataLegacy;
    }

}
