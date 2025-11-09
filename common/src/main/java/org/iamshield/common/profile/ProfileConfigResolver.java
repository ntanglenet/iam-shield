package org.iamshield.common.profile;

import org.iamshield.common.Profile;

public interface ProfileConfigResolver {

    Profile.ProfileName getProfileName();

    FeatureConfig getFeatureConfig(String feature);

    public enum FeatureConfig {
        ENABLED,
        DISABLED,
        UNCONFIGURED
    }

}
