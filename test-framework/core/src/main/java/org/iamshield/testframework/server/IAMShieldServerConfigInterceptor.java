package org.iamshield.testframework.server;

import org.iamshield.testframework.injection.InstanceContext;

import java.lang.annotation.Annotation;

public interface IAMShieldServerConfigInterceptor<T, S extends Annotation> {

    IAMShieldServerConfigBuilder intercept(IAMShieldServerConfigBuilder serverConfig, InstanceContext<T, S> instanceContext);

}
