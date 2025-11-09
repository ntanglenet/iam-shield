/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.iamshield.authorization.config;

import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.iamshield.authorization.AuthorizationService;
import org.iamshield.authorization.protection.ProtectionService;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.protocol.oidc.OIDCWellKnownProviderFactory;
import org.iamshield.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.iamshield.services.resources.RealmsResource;
import org.iamshield.urls.UrlType;
import org.iamshield.wellknown.WellKnownProvider;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UmaConfiguration extends OIDCConfigurationRepresentation {

    public static final UmaConfiguration create(IAMShieldSession session) {
        WellKnownProvider oidcProvider = session.getProvider(WellKnownProvider.class, OIDCWellKnownProviderFactory.PROVIDER_ID);
        OIDCConfigurationRepresentation oidcConfig = OIDCConfigurationRepresentation.class.cast(oidcProvider.getConfig());
        UmaConfiguration configuration = new UmaConfiguration();

        configuration.setIssuer(oidcConfig.getIssuer());
        configuration.setAuthorizationEndpoint(oidcConfig.getAuthorizationEndpoint());
        configuration.setTokenEndpoint(oidcConfig.getTokenEndpoint());
        configuration.setJwksUri(oidcConfig.getJwksUri());
        configuration.setRegistrationEndpoint(oidcConfig.getRegistrationEndpoint());
        configuration.setScopesSupported(oidcConfig.getScopesSupported());
        configuration.setResponseTypesSupported(oidcConfig.getResponseTypesSupported());
        configuration.setResponseModesSupported(oidcConfig.getResponseModesSupported());
        configuration.setGrantTypesSupported(oidcConfig.getGrantTypesSupported());
        configuration.setTokenEndpointAuthMethodsSupported(oidcConfig.getTokenEndpointAuthMethodsSupported());
        configuration.setTokenEndpointAuthSigningAlgValuesSupported(oidcConfig.getTokenEndpointAuthSigningAlgValuesSupported());
        configuration.setIntrospectionEndpoint(oidcConfig.getIntrospectionEndpoint());
        configuration.setLogoutEndpoint(oidcConfig.getLogoutEndpoint());

        UriBuilder backendUriBuilder = session.getContext().getUri(UrlType.BACKEND).getBaseUriBuilder();
        RealmModel realm = session.getContext().getRealm();

        configuration.setPermissionEndpoint(backendUriBuilder.clone().path(RealmsResource.class).path(RealmsResource.class, "getAuthorizationService").path(AuthorizationService.class, "getProtectionService").path(ProtectionService.class, "permission").build(realm.getName()).toString());
        configuration.setResourceRegistrationEndpoint(backendUriBuilder.clone().path(RealmsResource.class).path(RealmsResource.class, "getAuthorizationService").path(AuthorizationService.class, "getProtectionService").path(ProtectionService.class, "resource").build(realm.getName()).toString());
        configuration.setPolicyEndpoint(backendUriBuilder.clone().path(RealmsResource.class).path(RealmsResource.class, "getAuthorizationService").path(AuthorizationService.class, "getProtectionService").path(ProtectionService.class, "policy").build(realm.getName()).toString());

        return configuration;
    }

    @JsonProperty("resource_registration_endpoint")
    private String resourceRegistrationEndpoint;

    @JsonProperty("permission_endpoint")
    private String permissionEndpoint;
    
    @JsonProperty("policy_endpoint")
    private String policyEndpoint;

    public String getResourceRegistrationEndpoint() {
        return this.resourceRegistrationEndpoint;
    }

    void setResourceRegistrationEndpoint(String resourceRegistrationEndpoint) {
        this.resourceRegistrationEndpoint = resourceRegistrationEndpoint;
    }

    public String getPermissionEndpoint() {
        return this.permissionEndpoint;
    }

    void setPermissionEndpoint(String permissionEndpoint) {
        this.permissionEndpoint = permissionEndpoint;
    }
    
    public String getPolicyEndpoint() {
        return this.policyEndpoint;
    }

    void setPolicyEndpoint(String policyEndpoint) {
        this.policyEndpoint = policyEndpoint;
    }
}
