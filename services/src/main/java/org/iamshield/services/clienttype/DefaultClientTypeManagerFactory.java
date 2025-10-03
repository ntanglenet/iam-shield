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

package org.iamshield.services.clienttype;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.client.clienttype.ClientTypeException;
import org.iamshield.client.clienttype.ClientTypeManager;
import org.iamshield.client.clienttype.ClientTypeManagerFactory;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.representations.idm.ClientTypeRepresentation;
import org.iamshield.representations.idm.ClientTypesRepresentation;
import org.iamshield.util.JsonSerialization;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientTypeManagerFactory implements ClientTypeManagerFactory {

    private static final Logger logger = Logger.getLogger(DefaultClientTypeManagerFactory.class);

    private volatile List<ClientTypeRepresentation> globalClientTypes;

    @Override
    public ClientTypeManager create(IAMShieldSession session) {
        return new DefaultClientTypeManager(session, getGlobalClientTypes(session));
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "default";
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.CLIENT_TYPES);
    }

    protected List<ClientTypeRepresentation> getGlobalClientTypes(IAMShieldSession session) {
        if (globalClientTypes == null) {
            synchronized (this) {
                if (globalClientTypes == null) {
                    logger.info("Loading global client types");

                    try {
                        ClientTypesRepresentation globalTypesRep  = JsonSerialization.readValue(getClass().getResourceAsStream("/keycloak-default-client-types.json"), ClientTypesRepresentation.class);
                        this.globalClientTypes = DefaultClientTypeManager.validateAndCastConfiguration(session, globalTypesRep.getRealmClientTypes(), Collections.emptyList());
                    } catch (IOException e) {
                        logger.error("Failed to deserialize global proposed client types from JSON.");
                        throw ClientTypeException.Message.CLIENT_TYPE_FAILED_TO_LOAD.exception(e);
                    }
                }
            }
        }
        return globalClientTypes;
    }

}