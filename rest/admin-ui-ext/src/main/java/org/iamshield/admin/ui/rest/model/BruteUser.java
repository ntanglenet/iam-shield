package org.iamshield.admin.ui.rest.model;

import java.util.Map;
import org.iamshield.representations.idm.UserRepresentation;

public class BruteUser extends UserRepresentation {

    Map<String, Object> bruteForceStatus;

    public BruteUser(UserRepresentation user) {
        super(user);
    }

    public Map<String, Object> getBruteForceStatus() {
        return bruteForceStatus;
    }

    public void setBruteForceStatus(Map<String, Object> bruteForceStatus) {
        this.bruteForceStatus = bruteForceStatus;
    }
}
