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

package org.iamshield.protocol;

import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.Provider;
import org.iamshield.provider.ProviderFactory;

import jakarta.ws.rs.core.Response;
import java.net.URI;

/**
 * Provides a template/sample client config adapter file.  For example keycloak.json for our OIDC adapter.  keycloak-saml.xml for our SAML client adapter
 *
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface ClientInstallationProvider extends Provider, ProviderFactory<ClientInstallationProvider> {
    Response generateInstallation(IAMShieldSession session, RealmModel realm, ClientModel client, URI serverBaseUri);
    String getProtocol();
    String getDisplayType();
    String getHelpText();
    String getFilename();
    String getMediaType();
    boolean isDownloadOnly();
}
