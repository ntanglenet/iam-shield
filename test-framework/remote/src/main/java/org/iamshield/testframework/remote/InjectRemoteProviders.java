package org.iamshield.testframework.remote;

import org.iamshield.testframework.injection.LifeCycle;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface InjectRemoteProviders {

    LifeCycle lifecycle() default LifeCycle.GLOBAL;
}
