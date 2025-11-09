package org.iamshield.cookie;

import org.iamshield.provider.Provider;

public interface CookieProvider extends Provider {

    void set(CookieType cookieType, String value);

    void set(CookieType cookieType, String value, int maxAge);

    String get(CookieType cookieType);

    void expire(CookieType cookieType);

}
