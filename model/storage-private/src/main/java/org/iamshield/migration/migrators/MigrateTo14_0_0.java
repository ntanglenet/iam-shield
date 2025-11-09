/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.iamshield.migration.migrators;

import org.iamshield.migration.ModelVersion;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ModelException;
import org.iamshield.models.RealmModel;
import org.iamshield.representations.idm.ClientPoliciesRepresentation;
import org.iamshield.representations.idm.ClientProfilesRepresentation;
import org.iamshield.services.clientpolicy.ClientPolicyException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class MigrateTo14_0_0 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("14.0.0");

    @Override
    public void migrate(IAMShieldSession session) {
        session.realms()
                .getRealmsStream()
                .forEach(realm -> migrateRealm(session, realm));
    }

    private void migrateRealm(IAMShieldSession session, RealmModel realm) {
        try {
            session.clientPolicy().updateClientProfiles(realm, new ClientProfilesRepresentation());
            session.clientPolicy().updateClientPolicies(realm, new ClientPoliciesRepresentation());
        } catch (ClientPolicyException cpe) {
            throw new ModelException("Exception during migration client profiles or client policies", cpe);
        }
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }
}
