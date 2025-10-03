/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.quarkus.runtime.services.health;

import io.smallrye.health.api.AsyncHealthCheck;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.inject.Produces;
import org.eclipse.microprofile.health.Readiness;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.connections.infinispan.InfinispanConnectionProviderFactory;
import org.iamshield.quarkus.runtime.integration.QuarkusIAMShieldSessionFactory;

@ApplicationScoped
public class IAMShieldClusterReadyHealthCheckProducer {

    @Produces
    @Readiness
    @Dependent
    public AsyncHealthCheck createHealthCheck() {
        var sessionFactory = QuarkusIAMShieldSessionFactory.getInstance();
        InfinispanConnectionProviderFactory factory = (InfinispanConnectionProviderFactory) sessionFactory.getProviderFactory(InfinispanConnectionProvider.class);
        if (factory.isClusterHealthSupported()) {
            return new IAMShieldClusterReadyHealthCheck();
        } else {
            return null;
        }
    }
}
