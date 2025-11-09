package org.iamshield.testsuite.model;

import org.junit.Test;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.services.managers.RealmManager;
import org.iamshield.testsuite.AbstractIAMShieldTest;
import org.iamshield.testsuite.arquillian.annotation.ModelTest;
import org.iamshield.utils.ReservedCharValidator;

import java.util.List;

import static org.junit.Assert.fail;

public class BadRealmTest extends AbstractIAMShieldTest {
    private String name = "MyRealm";
    private String id = "MyId";
    private String script = "<script>alert(4)</script>";

    public void addTestRealms(List<RealmRepresentation> testRealms) {
    }

    @Test
    @ModelTest
    public void testBadRealmName(IAMShieldSession session) {
        RealmManager manager = new RealmManager(session);
        try {
            manager.createRealm(id, name + script);
            fail();
        } catch (ReservedCharValidator.ReservedCharException ex) {}
    }

    @Test
    @ModelTest
    public void testBadRealmId(IAMShieldSession session) {
        RealmManager manager = new RealmManager(session);
        try {
            manager.createRealm(id + script, name);
            fail();
        } catch (ReservedCharValidator.ReservedCharException ex) {}
    }
}
