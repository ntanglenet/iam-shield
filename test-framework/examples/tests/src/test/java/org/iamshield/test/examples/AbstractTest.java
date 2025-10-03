package org.iamshield.test.examples;

import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.realm.ManagedRealm;

public abstract class AbstractTest {

    @InjectRealm
    ManagedRealm realm;

}
