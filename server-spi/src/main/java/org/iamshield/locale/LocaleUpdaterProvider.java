package org.iamshield.locale;

import org.iamshield.models.UserModel;
import org.iamshield.provider.Provider;

public interface LocaleUpdaterProvider extends Provider {

    void updateUsersLocale(UserModel user, String locale);

    void updateLocaleCookie(String locale);

    void expireLocaleCookie();

}
