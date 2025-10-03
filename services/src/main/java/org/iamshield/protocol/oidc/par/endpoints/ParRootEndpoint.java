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
 */

package org.iamshield.protocol.oidc.par.endpoints;

import jakarta.ws.rs.Path;

import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.events.EventBuilder;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.protocol.oidc.ext.OIDCExtProvider;
import org.iamshield.protocol.oidc.ext.OIDCExtProviderFactory;
import org.iamshield.provider.EnvironmentDependentProviderFactory;

public class ParRootEndpoint implements OIDCExtProvider, OIDCExtProviderFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "par";

    private final IAMShieldSession session;
    private EventBuilder event;

    public ParRootEndpoint() {
        // for reflection
        this(null);
    }

    public ParRootEndpoint(IAMShieldSession session) {
        this.session = session;
    }

    @Path("/request")
    public ParEndpoint request() {
        return new ParEndpoint(session, event);
    }

    @Override
    public OIDCExtProvider create(IAMShieldSession session) {
        return new ParRootEndpoint(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.PAR);
    }

    @Override
    public void setEvent(EventBuilder event) {
        this.event = event;
    }

    @Override
    public void close() {
    }

}
