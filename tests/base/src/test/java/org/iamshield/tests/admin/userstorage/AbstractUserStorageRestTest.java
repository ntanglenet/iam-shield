package org.iamshield.tests.admin.userstorage;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Assertions;
import org.iamshield.common.util.MultivaluedHashMap;
import org.iamshield.models.LDAPConstants;
import org.iamshield.representations.idm.ComponentRepresentation;
import org.iamshield.storage.UserStorageProvider;
import org.iamshield.testframework.annotations.InjectAdminEvents;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.events.AdminEvents;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.tests.utils.admin.ApiUtil;

public class AbstractUserStorageRestTest {

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectAdminEvents
    AdminEvents adminEvents;

    protected String createComponent(ComponentRepresentation rep) {
        Response resp = managedRealm.admin().components().add(rep);
        Assertions.assertEquals(201, resp.getStatus());
        resp.close();
        String id = ApiUtil.getCreatedId(resp);

        adminEvents.clear();
        return id;
    }

    protected void removeComponent(String id) {
        managedRealm.admin().components().component(id).remove();
        adminEvents.clear();
    }

    protected ComponentRepresentation createBasicLDAPProviderRep() {
        ComponentRepresentation ldapRep = new ComponentRepresentation();
        ldapRep.setName("ldap2");
        ldapRep.setProviderId("ldap");
        ldapRep.setProviderType(UserStorageProvider.class.getName());
        ldapRep.setConfig(new MultivaluedHashMap<>());
        ldapRep.getConfig().putSingle("priority", Integer.toString(2));
        ldapRep.getConfig().putSingle(LDAPConstants.EDIT_MODE, UserStorageProvider.EditMode.WRITABLE.name());
        return ldapRep;
    }
}
