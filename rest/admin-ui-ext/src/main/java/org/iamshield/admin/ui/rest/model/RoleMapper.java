package org.iamshield.admin.ui.rest.model;

import org.iamshield.models.ClientModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;

public class RoleMapper {
    public static ClientRole convertToModel(RoleModel roleModel, RealmModel realm) {
        ClientModel clientModel = realm.getClientById(roleModel.getContainerId());
        if (clientModel==null) {
            throw new IllegalArgumentException("Could not find referenced client");
        }
        ClientRole clientRole = new ClientRole(roleModel.getId(), roleModel.getName(), roleModel.getDescription());
        clientRole.setClientId(clientModel.getId());
        clientRole.setClient(clientModel.getClientId());
        return clientRole;
    }
}
