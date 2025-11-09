package org.iamshield.testframework.conditions;

import org.iamshield.testframework.server.IAMShieldServer;

import java.lang.annotation.Annotation;

class DisabledForServersCondition extends AbstractDisabledForSupplierCondition {

    @Override
    Class<?> valueType() {
        return IAMShieldServer.class;
    }

    Class<? extends Annotation> annotation() {
        return DisabledForServers.class;
    }

}
