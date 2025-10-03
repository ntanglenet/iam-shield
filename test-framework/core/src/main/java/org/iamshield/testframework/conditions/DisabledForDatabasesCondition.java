package org.iamshield.testframework.conditions;

import org.iamshield.testframework.database.TestDatabase;

import java.lang.annotation.Annotation;

class DisabledForDatabasesCondition extends AbstractDisabledForSupplierCondition {

    @Override
    Class<?> valueType() {
        return TestDatabase.class;
    }

    Class<? extends Annotation> annotation() {
        return DisabledForDatabases.class;
    }

}
