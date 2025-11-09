/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import io.smallrye.health.api.AsyncHealthCheck;
import io.smallrye.mutiny.Uni;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.connections.infinispan.InfinispanConnectionProviderFactory;
import org.iamshield.infinispan.util.InfinispanUtils;
import org.iamshield.quarkus.runtime.integration.QuarkusIAMShieldSessionFactory;

import static org.iamshield.quarkus.runtime.services.health.IAMShieldReadyHealthCheck.DATE_FORMATTER;
import static org.iamshield.quarkus.runtime.services.health.IAMShieldReadyHealthCheck.FAILING_SINCE;

public class IAMShieldClusterReadyHealthCheck implements AsyncHealthCheck {

    private final AtomicReference<Instant> failingSince = new AtomicReference<>();

    @Override
    public Uni<HealthCheckResponse> call() {
        var builder = HealthCheckResponse.named("IAMShield cluster health check").up();
        if (InfinispanUtils.isRemoteInfinispan()) {
            return Uni.createFrom().item(builder.build());
        }
        var sessionFactory = QuarkusIAMShieldSessionFactory.getInstance();
        InfinispanConnectionProviderFactory factory = (InfinispanConnectionProviderFactory) sessionFactory.getProviderFactory(InfinispanConnectionProvider.class);
        if (factory.isClusterHealthy()) {
            failingSince.set(null);
        } else {
            builder.down();
            Instant failingTime = failingSince.updateAndGet(IAMShieldReadyHealthCheck::createInstanceIfNeeded);
            builder.withData(FAILING_SINCE, DATE_FORMATTER.format(failingTime));
        }
        return Uni.createFrom().item(builder.build());
    }
}
