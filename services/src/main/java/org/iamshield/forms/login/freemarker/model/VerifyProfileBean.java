package org.iamshield.forms.login.freemarker.model;

import java.util.stream.Stream;

import jakarta.ws.rs.core.MultivaluedMap;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserModel;
import org.iamshield.userprofile.UserProfile;
import org.iamshield.userprofile.UserProfileContext;
import org.iamshield.userprofile.UserProfileProvider;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class VerifyProfileBean extends AbstractUserProfileBean {

    private final UserModel user;

    public VerifyProfileBean(UserModel user, MultivaluedMap<String, String> formData, IAMShieldSession session) {
        super(formData);
        this.user = user;
        init(session, false);
    }

    @Override
    protected UserProfile createUserProfile(UserProfileProvider provider) {
        return provider.create(UserProfileContext.UPDATE_PROFILE, user);
    }

    @Override
    protected Stream<String> getAttributeDefaultValues(String name){
        return user.getAttributeStream(name);
    }
    
    @Override 
    public String getContext() {
        return UserProfileContext.UPDATE_PROFILE.name();
    }

}
