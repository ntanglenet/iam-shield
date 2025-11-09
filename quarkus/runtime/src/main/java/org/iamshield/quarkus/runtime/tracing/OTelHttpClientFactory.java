/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.quarkus.runtime.tracing;

import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.config.TracingOptions;
import org.iamshield.connections.httpclient.DefaultHttpClientFactory;
import org.iamshield.connections.httpclient.HttpClientBuilder;
import org.iamshield.connections.httpclient.HttpClientFactory;
import org.iamshield.connections.httpclient.HttpClientProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.provider.Provider;
import org.iamshield.quarkus.runtime.configuration.Configuration;
import org.iamshield.tracing.TracingProvider;

import java.util.Set;

/**
 * The traced {@link HttpClientFactory} for {@link HttpClientProvider HttpClientProvider's} used by Keycloak for outbound HTTP calls which are traced.
 */
public class OTelHttpClientFactory extends DefaultHttpClientFactory implements EnvironmentDependentProviderFactory {
    public static final String PROVIDER_ID = "opentelemetry";

    private static OTelHttpClientBuilder BUILDER_SINGLETON;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public HttpClientProvider create(IAMShieldSession session) {
        if (BUILDER_SINGLETON == null) {
            BUILDER_SINGLETON = new OTelHttpClientBuilder((OTelTracingProvider) session.getProvider(TracingProvider.class));
        }
        return super.create(session);
    }

    @Override
    protected HttpClientBuilder newHttpClientBuilder() {
        return BUILDER_SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(Config.scope("connectionsHttpClient", "default"));
    }

    @Override
    public int order() {
        return super.order() + 10;
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return Set.of(TracingProvider.class);
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.OPENTELEMETRY) && Configuration.isTrue(TracingOptions.TRACING_ENABLED);
    }
}
