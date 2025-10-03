package org.iamshield.testframework.remote.timeoffset;

import org.iamshield.testframework.injection.LifeCycle;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InjectTimeOffSet {

    LifeCycle lifecycle() default LifeCycle.METHOD;

    int offset() default 0;
}
