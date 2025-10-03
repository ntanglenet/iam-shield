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

package org.iamshield.services.clientpolicy.executor;

import jakarta.ws.rs.core.MultivaluedMap;

import org.iamshield.OAuthErrorException;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.services.clientpolicy.ClientPolicyContext;
import org.iamshield.services.clientpolicy.ClientPolicyException;
import org.iamshield.services.clientpolicy.context.ClientCRUDContext;
import org.iamshield.services.clientpolicy.context.ResourceOwnerPasswordCredentialsContext;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class RejectResourceOwnerPasswordCredentialsGrantExecutor implements ClientPolicyExecutorProvider<RejectResourceOwnerPasswordCredentialsGrantExecutor.Configuration> {

    private final IAMShieldSession session;
    private Configuration configuration;

    public RejectResourceOwnerPasswordCredentialsGrantExecutor(IAMShieldSession session) {
        this.session = session;
    }

    @Override
    public void setupConfiguration(Configuration config) {
        this.configuration = config;
    }

    @Override
    public Class<Configuration> getExecutorConfigurationClass() {
        return Configuration.class;
    }

    public static class Configuration extends ClientPolicyExecutorConfigurationRepresentation {
        @JsonProperty("auto-configure")
        protected Boolean autoConfigure;

        public Boolean isAutoConfigure() {
            return autoConfigure;
        }

        public void setAutoConfigure(Boolean autoConfigure) {
            this.autoConfigure = autoConfigure;
        }
    }

    @Override
    public String getProviderId() {
        return RejectResourceOwnerPasswordCredentialsGrantExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case REGISTER:
            case UPDATE:
                ClientCRUDContext clientUpdateContext = (ClientCRUDContext)context;
                autoConfigure(clientUpdateContext.getProposedClientRepresentation());
                validate(clientUpdateContext.getProposedClientRepresentation());
                break;
            case RESOURCE_OWNER_PASSWORD_CREDENTIALS_REQUEST:
                ResourceOwnerPasswordCredentialsContext ropcContext = (ResourceOwnerPasswordCredentialsContext)context;
                executeOnAuthorizationRequest(ropcContext.getParams());
                return;
            default:
                return;
        }
    }

    private void autoConfigure(ClientRepresentation rep) {
        if (configuration.isAutoConfigure())
            rep.setDirectAccessGrantsEnabled(Boolean.FALSE);
    }

    private void validate(ClientRepresentation rep) throws ClientPolicyException {
        boolean isResourceOwnerPasswordCredentialsGrantEnabled = rep.isDirectAccessGrantsEnabled().booleanValue();
        if (!isResourceOwnerPasswordCredentialsGrantEnabled) return;
        throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: resource owner password credentials grant enabled");
    }

    private void executeOnAuthorizationRequest(MultivaluedMap<String, String> params) throws ClientPolicyException {
        // Before client policies operation, Token Endpoint logic has already checked whether resource owner password credentials grant is activated for a client.
        // This method rejects resource owner password credentials grant regardless of client setting for allowing resource owner password credentials grant.
        throw new ClientPolicyException(OAuthErrorException.INVALID_GRANT, "resource owner password credentials grant is prohibited.");
    }

}