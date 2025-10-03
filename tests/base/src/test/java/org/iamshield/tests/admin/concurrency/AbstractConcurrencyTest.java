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

package org.iamshield.tests.admin.concurrency;

import org.jboss.logging.Logger;
import org.iamshield.OAuth2Constants;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.testframework.admin.AdminClientFactory;
import org.iamshield.testframework.annotations.InjectAdminClientFactory;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.config.Config;
import org.iamshield.testframework.realm.ManagedRealm;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public abstract class AbstractConcurrencyTest {

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectAdminClientFactory
    static AdminClientFactory clientFactory;

    private static final Logger LOGGER = Logger.getLogger(AbstractConcurrencyTest.class);

    private static final int DEFAULT_THREADS = 4;

    public static final String REALM_NAME = "default";
    public static final String MASTER_REALM_NAME = "master";

    // If enabled only one request is allowed at the time. Useful for checking that test is working.
    private static final boolean SYNCHRONIZED = false;

    protected void run(final IAMShieldRunnable... runnables) {
        run(DEFAULT_THREADS, runnables);
    }

    public static void run(final int numThreads, final IAMShieldRunnable... runnables) {
        final ExecutorService service = SYNCHRONIZED
                ? Executors.newSingleThreadExecutor()
                : Executors.newFixedThreadPool(numThreads);

        ThreadLocal<IAMShield> keycloaks = new ThreadLocal<IAMShield>() {
            @Override
            protected IAMShield initialValue() {
                return clientFactory.create().realm(MASTER_REALM_NAME)
                        .clientId(Config.getAdminClientId())
                        .clientSecret(Config.getAdminClientSecret())
                        .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                        .build();
            }
        };

        AtomicInteger currentThreadIndex = new AtomicInteger();
        Collection<Callable<Void>> tasks = new LinkedList<>();
        Collection<Throwable> failures = new ConcurrentLinkedQueue<>();
        final List<Callable<Void>> runnablesToTasks = new LinkedList<>();

        // Track all used admin clients, so they can be closed after the test
        Set<IAMShield> usedKeycloaks = Collections.synchronizedSet(new HashSet<>());

        for (IAMShieldRunnable runnable : runnables) {
            runnablesToTasks.add(() -> {
                int arrayIndex = currentThreadIndex.getAndIncrement() % numThreads;
                try {
                    IAMShield keycloak = keycloaks.get();
                    usedKeycloaks.add(keycloak);

                    runnable.run(arrayIndex % numThreads, keycloak, keycloak.realm(REALM_NAME));
                } catch (Throwable ex) {
                    failures.add(ex);
                }
                return null;
            });
        }

        tasks.addAll(runnablesToTasks);

        try {
            service.invokeAll(tasks);
            service.shutdown();
            service.awaitTermination(3, TimeUnit.MINUTES);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        } finally {
            for (IAMShield keycloak : usedKeycloaks) {
                try {
                    keycloak.close();
                } catch (Exception e) {
                    failures.add(e);
                }
            }
        }

        if (! failures.isEmpty()) {
            RuntimeException ex = new RuntimeException("There were failures in threads. Failures count: " + failures.size());
            failures.forEach(ex::addSuppressed);
            failures.forEach(e -> LOGGER.error(e.getMessage(), e));
            throw ex;
        }
    }


    public interface IAMShieldRunnable {

        void run(int threadIndex, IAMShield keycloak, RealmResource realm) throws Throwable;

    }

}
