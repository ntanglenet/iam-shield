package org.iamshield.admin.ui.rest;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;

public abstract class RoleMappingResource {
    protected final IAMShieldSession session;
    protected final RealmModel realm;
    protected final AdminPermissionEvaluator auth;

    public RoleMappingResource(IAMShieldSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }
}
