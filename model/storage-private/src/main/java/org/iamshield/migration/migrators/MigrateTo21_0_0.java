package org.iamshield.migration.migrators;

import org.iamshield.migration.ModelVersion;
import org.iamshield.models.AccountRoles;
import org.iamshield.models.ClientModel;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.representations.idm.RealmRepresentation;

public class MigrateTo21_0_0 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("21.0.0");

    @Override
    public void migrate(IAMShieldSession session) {
        session.realms().getRealmsStream().forEach(this::updateAdminTheme);
    }

    @Override
    public void migrateImport(IAMShieldSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        updateAdminTheme(realm);
    }

    private void updateAdminTheme(RealmModel realm) {
        String adminTheme = realm.getAdminTheme();
        if ("keycloak".equals(adminTheme) || "rh-sso".equals(adminTheme)) {
            realm.setAdminTheme("keycloak.v2");
        }
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }
}
