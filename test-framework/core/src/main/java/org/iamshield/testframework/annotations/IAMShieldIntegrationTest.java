package org.iamshield.testframework.annotations;

import org.iamshield.testframework.server.DefaultIAMShieldServerConfig;
import org.iamshield.testframework.server.IAMShieldServerConfig;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface IAMShieldIntegrationTest {

    Class<? extends IAMShieldServerConfig> config() default DefaultIAMShieldServerConfig.class;

}
