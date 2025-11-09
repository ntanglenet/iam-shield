package org.iamshield.testframework.oauth.annotations;

import org.iamshield.testframework.injection.LifeCycle;
import org.iamshield.testframework.oauth.DefaultOAuthIdentityProviderConfig;
import org.iamshield.testframework.oauth.OAuthIdentityProviderConfig;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InjectOAuthIdentityProvider {

    LifeCycle lifecycle() default LifeCycle.GLOBAL;

    Class<? extends OAuthIdentityProviderConfig> config() default DefaultOAuthIdentityProviderConfig.class;

}
