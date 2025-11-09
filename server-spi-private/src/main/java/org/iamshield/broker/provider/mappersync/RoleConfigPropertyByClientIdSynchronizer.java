/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.broker.provider.mappersync;

import org.iamshield.broker.provider.ConfigConstants;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.utils.IAMShieldModelUtils;

import java.util.Map;
import java.util.function.Consumer;

/**
 * Updates a role reference in a mapper config, when a client ID changes.
 *
 * @author <a href="mailto:daniel.fesenmeyer@bosch.io">Daniel Fesenmeyer</a>
 */
public class RoleConfigPropertyByClientIdSynchronizer implements ConfigSynchronizer<ClientModel.ClientIdChangeEvent> {

    public static final RoleConfigPropertyByClientIdSynchronizer INSTANCE =
            new RoleConfigPropertyByClientIdSynchronizer();

    private RoleConfigPropertyByClientIdSynchronizer() {
        // noop
    }

    @Override
    public Class<ClientModel.ClientIdChangeEvent> getEventClass() {
        return ClientModel.ClientIdChangeEvent.class;
    }

    @Override
    public void handleEvent(ClientModel.ClientIdChangeEvent event) {
        // find all mappers that have a role config property that maps to a role associated with the changed client.
        event.getIAMShieldSession().identityProviders().getMappersStream(Map.of(ConfigConstants.ROLE, event.getPreviousClientId() + ".*"), null, null)
                .forEach(idpMapper -> {
                    String currentRoleValue = idpMapper.getConfig().get(ConfigConstants.ROLE);
                    String configuredRoleName = IAMShieldModelUtils.parseRole(currentRoleValue)[1];
                    String newRoleValue = IAMShieldModelUtils.buildRoleQualifier(event.getNewClientId(), configuredRoleName);
                    idpMapper.getConfig().put(ConfigConstants.ROLE, newRoleValue);
                    logEventProcessed(ConfigConstants.ROLE, currentRoleValue, newRoleValue, event.getUpdatedClient().getRealm().getName(),
                            idpMapper.getName(), idpMapper.getIdentityProviderAlias());
                    event.getIAMShieldSession().identityProviders().updateMapper(idpMapper);
                });
    }
}
