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
package org.iamshield.quarkus.runtime.integration.web;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.services.x509.X509ClientCertificateLookup;
import org.iamshield.services.x509.X509ClientCertificateLookupFactory;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class VertxClientCertificateLookupFactory implements X509ClientCertificateLookupFactory {

    private static X509ClientCertificateLookup SINGLETON;

    @Override
    public X509ClientCertificateLookup create(IAMShieldSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        SINGLETON = new VertxClientCertificateLookup();
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "quarkus";
    }

    @Override
    public int order() {
        return 100;
    }
}
