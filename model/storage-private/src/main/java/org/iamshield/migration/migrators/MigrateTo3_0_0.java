/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.migration.migrators;


import org.iamshield.migration.ModelVersion;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.representations.idm.RealmRepresentation;

import java.util.Objects;

import static org.iamshield.models.AccountRoles.MANAGE_ACCOUNT;
import static org.iamshield.models.AccountRoles.MANAGE_ACCOUNT_LINKS;
import static org.iamshield.models.Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;
import static org.iamshield.models.Constants.defaultClients;

/**
 * @author <a href="mailto:bburke@redhat.com">Bill Burke</a>
 */
public class MigrateTo3_0_0 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("3.0.0");

    @Override
    public void migrate(IAMShieldSession session) {
        session.realms().getRealmsStream().forEach(this::migrateRealm);
    }

    @Override
    public void migrateImport(IAMShieldSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        migrateRealm(realm);
    }

    protected void migrateRealm(RealmModel realm) {
        realm.getClientsStream()
                .filter(clientModel -> defaultClients.contains(clientModel.getId()))
                .filter(clientModel -> Objects.isNull(clientModel.getProtocol()))
                .forEach(clientModel -> clientModel.setProtocol("openid-connect"));

        ClientModel client = realm.getClientByClientId(ACCOUNT_MANAGEMENT_CLIENT_ID);
        if (client == null) return;
        RoleModel linkRole = client.getRole(MANAGE_ACCOUNT_LINKS);
        if (linkRole == null) {
            client.addRole(MANAGE_ACCOUNT_LINKS);
        }
        RoleModel manageAccount = client.getRole(MANAGE_ACCOUNT);
        if (manageAccount == null) return;
        RoleModel manageAccountLinks = client.getRole(MANAGE_ACCOUNT_LINKS);
        manageAccount.addCompositeRole(manageAccountLinks);
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }
}
