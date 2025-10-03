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

package org.iamshield.services.clientregistration.policy.impl;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.ClientModel;
import org.iamshield.models.ClientScopeModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.services.clientregistration.ClientRegistrationContext;
import org.iamshield.services.clientregistration.ClientRegistrationProvider;
import org.iamshield.services.clientregistration.policy.ClientRegistrationPolicy;
import org.iamshield.services.clientregistration.policy.ClientRegistrationPolicyException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientScopesClientRegistrationPolicy implements ClientRegistrationPolicy {

    private static final Logger logger = Logger.getLogger(ClientScopesClientRegistrationPolicy.class);

    private final IAMShieldSession session;
    private final RealmModel realm;
    private final ComponentModel componentModel;

    public ClientScopesClientRegistrationPolicy(IAMShieldSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
        this.realm = session.realms().getRealm(componentModel.getParentId());
    }

    @Override
    public void beforeRegister(ClientRegistrationContext context) throws ClientRegistrationPolicyException {
        List<String> requestedDefaultScopeNames = context.getClient().getDefaultClientScopes();
        List<String> requestedOptionalScopeNames = context.getClient().getOptionalClientScopes();

        List<String> allowedScopeNames = new ArrayList<>();
        allowedScopeNames.addAll(getAllowedScopeNames(realm, true));
        allowedScopeNames.addAll(getAllowedScopeNames(realm, false));


        checkClientScopesAllowed(requestedDefaultScopeNames, allowedScopeNames);
        checkClientScopesAllowed(requestedOptionalScopeNames, allowedScopeNames);
    }

    @Override
    public void afterRegister(ClientRegistrationContext context, ClientModel clientModel) {

    }

    @Override
    public void beforeUpdate(ClientRegistrationContext context, ClientModel clientModel) throws ClientRegistrationPolicyException {
        List<String> requestedDefaultScopeNames = new LinkedList<>();
        List<String> requestedOptionalScopeNames = new LinkedList<>();

        if(context.getClient().getDefaultClientScopes() != null) {
            requestedDefaultScopeNames.addAll(context.getClient().getDefaultClientScopes());
        }
        if(context.getClient().getOptionalClientScopes() != null) {
            requestedOptionalScopeNames.addAll(context.getClient().getOptionalClientScopes());
        }

        // Allow scopes, which were already presented before
        requestedDefaultScopeNames.removeAll(clientModel.getClientScopes(true).keySet());
        requestedOptionalScopeNames.removeAll(clientModel.getClientScopes(false).keySet());

        List<String> allowedScopeNames = new ArrayList<>();
        allowedScopeNames.addAll(getAllowedScopeNames(realm, true));
        allowedScopeNames.addAll(getAllowedScopeNames(realm, false));

        checkClientScopesAllowed(requestedDefaultScopeNames, allowedScopeNames);
        checkClientScopesAllowed(requestedOptionalScopeNames, allowedScopeNames);
    }

    @Override
    public void afterUpdate(ClientRegistrationContext context, ClientModel clientModel) {

    }

    @Override
    public void beforeView(ClientRegistrationProvider provider, ClientModel clientModel) throws ClientRegistrationPolicyException {

    }

    @Override
    public void beforeDelete(ClientRegistrationProvider provider, ClientModel clientModel) throws ClientRegistrationPolicyException {

    }

    private void checkClientScopesAllowed(List<String> requestedScopes, List<String> allowedScopes) throws ClientRegistrationPolicyException {
        if (requestedScopes != null) {
            for (String requested : requestedScopes) {
                if (!allowedScopes.contains(requested)) {
                    logger.warnf("Requested scope '%s' not trusted in the list: %s", requested, allowedScopes.toString());
                    throw new ClientRegistrationPolicyException("Not permitted to use specified clientScope");
                }
            }
        }
    }

    private List<String> getAllowedScopeNames(RealmModel realm, boolean defaultScopes) {
        List<String> allAllowed = new LinkedList<>();

        // Add client scopes allowed by config
        List<String> allowedScopesConfig = componentModel.getConfig().getList(ClientScopesClientRegistrationPolicyFactory.ALLOWED_CLIENT_SCOPES);
        if (allowedScopesConfig != null) {
            allAllowed.addAll(allowedScopesConfig);
        }

        // If allowDefaultScopes, then realm default scopes are allowed as default scopes (+ optional scopes are allowed as optional scopes)
        boolean allowDefaultScopes = componentModel.get(ClientScopesClientRegistrationPolicyFactory.ALLOW_DEFAULT_SCOPES, true);
        if (allowDefaultScopes) {
            allAllowed.addAll(realm.getDefaultClientScopesStream(defaultScopes).map(ClientScopeModel::getName).collect(Collectors.toList()));
        }

        return allAllowed;
    }
}
