package org.iamshield.testsuite.cluster;

import org.junit.Before;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.arquillian.ContainerInfo;

/**
 *
 * @author tkyjovsk
 */
public abstract class AbstractInvalidationClusterTestWithTestRealm<T, TR> extends AbstractInvalidationClusterTest<T, TR> {

    protected String testRealmName = null;
    
    @Before
    public void createTestRealm() {
        createTestRealm(frontendNode());
    }
    
    protected void createTestRealm(ContainerInfo node) {
        RealmRepresentation r = createTestRealmRepresentation();
        getAdminClientFor(node).realms().create(r);
        testRealmName = r.getRealm();
    }
    
}
