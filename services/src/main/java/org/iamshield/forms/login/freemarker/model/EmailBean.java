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
package org.iamshield.forms.login.freemarker.model;

import java.util.stream.Stream;

import jakarta.ws.rs.core.MultivaluedMap;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserModel;
import org.iamshield.userprofile.UserProfile;
import org.iamshield.userprofile.UserProfileContext;
import org.iamshield.userprofile.UserProfileProvider;

public class EmailBean extends AbstractUserProfileBean {

	private final UserModel user;
	public EmailBean(UserModel user, MultivaluedMap<String, String> formData, IAMShieldSession session) {
		super(formData);
		this.user = user;
		init(session, false);
	}

	public String getValue() {
		return formData != null ? formData.getFirst("email") : user.getEmail();
	}

	@Override
	protected UserProfile createUserProfile(UserProfileProvider provider) {
		return provider.create(UserProfileContext.UPDATE_EMAIL, user);
	}

	@Override
	protected Stream<String> getAttributeDefaultValues(String name) {
		return user.getAttributeStream(name);
	}

	@Override
	public String getContext() {
		return UserProfileContext.UPDATE_PROFILE.name();
	}
}
