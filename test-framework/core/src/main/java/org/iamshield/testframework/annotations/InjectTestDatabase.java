package org.iamshield.testframework.annotations;

import org.iamshield.testframework.database.DatabaseConfig;
import org.iamshield.testframework.database.DefaultDatabaseConfig;
import org.iamshield.testframework.injection.LifeCycle;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InjectTestDatabase {

    LifeCycle lifecycle() default LifeCycle.GLOBAL;

    Class<? extends DatabaseConfig> config() default DefaultDatabaseConfig.class;
}
