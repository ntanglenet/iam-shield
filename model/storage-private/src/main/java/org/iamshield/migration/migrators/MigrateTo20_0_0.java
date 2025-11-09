package org.iamshield.migration.migrators;

import org.iamshield.migration.ModelVersion;
import org.iamshield.models.AccountRoles;
import org.iamshield.models.ClientModel;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.representations.idm.RealmRepresentation;

public class MigrateTo20_0_0 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("20.0.0");

    @Override
    public void migrate(IAMShieldSession session) {

        session.realms().getRealmsStream().forEach(this::addViewGroupsRole);
    }

    @Override
    public void migrateImport(IAMShieldSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        addViewGroupsRole(realm);
    }

    private void addViewGroupsRole(RealmModel realm) {
        ClientModel accountClient = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        if (accountClient != null && accountClient.getRole(AccountRoles.VIEW_GROUPS) == null) {
            RoleModel viewGroupsRole = accountClient.addRole(AccountRoles.VIEW_GROUPS);
            viewGroupsRole.setDescription("${role_" + AccountRoles.VIEW_GROUPS + "}");
            ClientModel accountConsoleClient = realm.getClientByClientId(Constants.ACCOUNT_CONSOLE_CLIENT_ID);
            accountConsoleClient.addScopeMapping(viewGroupsRole);
        }
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }
}
