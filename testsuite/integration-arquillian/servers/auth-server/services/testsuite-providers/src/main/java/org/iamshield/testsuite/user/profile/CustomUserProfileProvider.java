package org.iamshield.testsuite.user.profile;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserModel;
import org.iamshield.representations.userprofile.config.UPAttributeRequired;
import org.iamshield.representations.userprofile.config.UPConfig;
import org.iamshield.userprofile.DeclarativeUserProfileProvider;
import org.iamshield.userprofile.UserProfile;
import org.iamshield.userprofile.UserProfileContext;
import org.iamshield.userprofile.config.UPConfigUtils;

import java.util.Map;
import java.util.Set;

public class CustomUserProfileProvider extends DeclarativeUserProfileProvider {

    public CustomUserProfileProvider(IAMShieldSession session, CustomUserProfileProviderFactory factory) {
        super(session, factory);
        UPConfig upConfig = getConfiguration();

        upConfig.getAttribute(UserModel.FIRST_NAME).setRequired(null);
        upConfig.getAttribute(UserModel.LAST_NAME).setRequired(null);
        upConfig.getAttribute(UserModel.EMAIL).setRequired(null);

        setConfiguration(upConfig);
    }

    @Override
    public UserProfile create(UserProfileContext context, UserModel user) {
        return this.create(context, user.getAttributes(), user);
    }

    @Override
    public UserProfile create(UserProfileContext context, Map<String, ?> attributes, UserModel user) {
        return super.create(context, attributes, user);
    }

    @Override
    public UserProfile create(UserProfileContext context, Map<String, ?> attributes) {
        return this.create(context, attributes, (UserModel) null);
    }

}
