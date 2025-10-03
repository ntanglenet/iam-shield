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
package org.iamshield.adapters.saml.elytron;

import javax.security.auth.callback.CallbackHandler;

import org.iamshield.adapters.saml.SamlAuthenticator;
import org.iamshield.adapters.saml.SamlDeployment;
import org.iamshield.adapters.saml.SamlSession;
import org.iamshield.adapters.saml.SamlSessionStore;
import org.iamshield.adapters.saml.profile.SamlAuthenticationHandler;
import org.iamshield.adapters.saml.profile.webbrowsersso.BrowserHandler;
import org.iamshield.adapters.spi.HttpFacade;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronSamlAuthenticator extends SamlAuthenticator {
    private final CallbackHandler callbackHandler;
    private final ElytronHttpFacade facade;

    public ElytronSamlAuthenticator(ElytronHttpFacade facade, SamlDeployment samlDeployment, CallbackHandler callbackHandler) {
        super(facade, samlDeployment, facade.getSessionStore());
        this.callbackHandler = callbackHandler;
        this.facade = facade;
    }

    @Override
    protected void completeAuthentication(SamlSession samlSession) {
        facade.authenticationComplete(samlSession);
    }

    @Override
    protected SamlAuthenticationHandler createBrowserHandler(HttpFacade facade, SamlDeployment deployment, SamlSessionStore sessionStore) {
        return new BrowserHandler(facade, deployment, sessionStore);
    }
}
