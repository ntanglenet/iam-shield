package org.iamshield.testframework.realm;

import org.iamshield.representations.idm.CredentialRepresentation;
import org.iamshield.representations.idm.GroupRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;

class Representations {

    private Representations() {
    }

    static RoleRepresentation toRole(String roleName, boolean asClientRole) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        role.setClientRole(asClientRole);
        return role;
    }

    static GroupRepresentation toGroup(String groupName) {
        GroupRepresentation group = new GroupRepresentation();
        group.setName(groupName);
        return group;
    }

    static CredentialRepresentation toCredential(String type, String value) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(type);
        credential.setValue(value);
        return credential;
    }

}
