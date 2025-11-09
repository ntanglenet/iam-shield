package org.iamshield.testsuite.util;

import org.iamshield.admin.client.resource.ClientResource;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.models.Constants;
import org.iamshield.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.representations.idm.UserRepresentation;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;

import static org.iamshield.testsuite.admin.ApiUtil.findClientByClientId;
import static org.iamshield.testsuite.admin.ApiUtil.findProtocolMapperByName;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>.
 */
public class ClientManager {

    private static RealmResource realm;

    private ClientManager() {
    }

    public static ClientManager realm(RealmResource realm) {
        ClientManager.realm = realm;
        return new ClientManager();
    }

    public ClientManagerBuilder clientId(String clientId) {
        return new ClientManagerBuilder(findClientByClientId(realm, clientId));
    }

    public class ClientManagerBuilder {

        private final ClientResource clientResource;

        public ClientManagerBuilder(ClientResource clientResource) {
            this.clientResource = clientResource;
        }

        public void renameTo(String newName) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setClientId(newName);
            clientResource.update(app);
        }

        public void enabled(Boolean enabled) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setEnabled(enabled);
            clientResource.update(app);
        }

        public void setServiceAccountsEnabled(Boolean enabled) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setServiceAccountsEnabled(enabled);
            clientResource.update(app);
        }

        public void updateAttribute(String attribute, String value) {
            ClientRepresentation app = clientResource.toRepresentation();
            if (app.getAttributes() == null) {
                app.setAttributes(new LinkedHashMap<String, String>());
            }
            app.getAttributes().put(attribute, value);
            clientResource.update(app);
        }

        public ClientManagerBuilder directAccessGrant(Boolean enable) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setDirectAccessGrantsEnabled(enable);
            clientResource.update(app);
            return this;
        }

        public ClientManagerBuilder standardFlow(Boolean enable) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setStandardFlowEnabled(enable);
            clientResource.update(app);
            return this;
        }

        public ClientManagerBuilder implicitFlow(Boolean enable) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setImplicitFlowEnabled(enable);
            clientResource.update(app);
            return this;
        }

        public ClientManagerBuilder alwaysUseLightweightAccessToken(boolean enable) {
            updateAttribute(Constants.USE_LIGHTWEIGHT_ACCESS_TOKEN_ENABLED, String.valueOf(enable));
            return this;
        }

        public ClientManagerBuilder fullScopeAllowed(boolean enable) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setFullScopeAllowed(enable);
            clientResource.update(app);
            return this;
        }

        public void addClientScope(String clientScopeId, boolean defaultScope) {
            if (defaultScope) {
                clientResource.addDefaultClientScope(clientScopeId);
            } else {
                clientResource.addOptionalClientScope(clientScopeId);
            }
        }

        public void removeClientScope(String clientScopeId, boolean defaultScope) {
            if (defaultScope) {
                clientResource.removeDefaultClientScope(clientScopeId);
            } else {
                clientResource.removeOptionalClientScope(clientScopeId);
            }
        }

        public void consentRequired(boolean enable) {
            ClientRepresentation app = clientResource.toRepresentation();
            app.setConsentRequired(enable);
            clientResource.update(app);
        }

        public ClientManagerBuilder addProtocolMapper(ProtocolMapperRepresentation protocolMapper) {
            clientResource.getProtocolMappers().createMapper(protocolMapper);
            return this;
        }

        public void addScopeMapping(RoleRepresentation newRole) {
            clientResource.getScopeMappings().realmLevel().add(Collections.singletonList(newRole));
        }

        public ClientManagerBuilder removeProtocolMapper(String protocolMapperName) {
            ProtocolMapperRepresentation rep = findProtocolMapperByName(clientResource, protocolMapperName);
            clientResource.getProtocolMappers().delete(rep.getId());
            return this;
        }

        public void removeScopeMapping(RoleRepresentation newRole) {
            clientResource.getScopeMappings().realmLevel().remove(Collections.singletonList(newRole));
        }

        public ClientManagerBuilder addRedirectUris(String... redirectUris) {
            ClientRepresentation app = clientResource.toRepresentation();
            if (app.getRedirectUris() == null) {
                app.setRedirectUris(new LinkedList<String>());
            }
            for (String redirectUri : redirectUris) {
                app.getRedirectUris().add(redirectUri);
            }
            clientResource.update(app);
            return this;
        }

        public void removeRedirectUris(String... redirectUris) {
            ClientRepresentation app = clientResource.toRepresentation();
            for (String redirectUri : redirectUris) {
                if (app.getRedirectUris() != null) {
                    app.getRedirectUris().remove(redirectUri);
                }
            }
            clientResource.update(app);
        }

        public void setPostLogoutRedirectUri(List<String> postLogoutRedirectUris) {
            ClientRepresentation app = clientResource.toRepresentation();
            OIDCAdvancedConfigWrapper.fromClientRepresentation(app).setPostLogoutRedirectUris(postLogoutRedirectUris);
            clientResource.update(app);
        }

        public ClientManagerBuilder addWebOrigins(String... webOrigins) {
            ClientRepresentation app = clientResource.toRepresentation();
            if (app.getWebOrigins() == null) {
                app.setWebOrigins(new LinkedList<String>());
            }
            for (String webOrigin : webOrigins) {
                app.getWebOrigins().add(webOrigin);
            }
            clientResource.update(app);
            return this;
        }

        public void removeWebOrigins(String... webOrigins) {
            ClientRepresentation app = clientResource.toRepresentation();
            for (String webOrigin : webOrigins) {
                if (app.getWebOrigins() != null) {
                    app.getWebOrigins().remove(webOrigin);
                }
            }
            clientResource.update(app);
        }

        // Set valid values of "request_uri" parameter
        public void setRequestUris(String... requestUris) {
            ClientRepresentation app = clientResource.toRepresentation();
            OIDCAdvancedConfigWrapper.fromClientRepresentation(app).setRequestUris(Arrays.asList(requestUris));
            clientResource.update(app);
        }

        public UserRepresentation getServiceAccountUser() {
            return clientResource.getServiceAccountUser();
        }
    }
}