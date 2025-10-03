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

package org.iamshield.testsuite.admin.concurrency;

import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.AbstractIAMShieldTest;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.utils.tls.TLSUtils;

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
@Deprecated(forRemoval = true)
public abstract class AbstractConcurrencyTest extends AbstractTestRealmIAMShieldTest {

    private static final int DEFAULT_THREADS = 4;
    private static final int DEFAULT_NUMBER_OF_EXECUTIONS = 20 * DEFAULT_THREADS;

    public static final String REALM_NAME = "test";

    // If enabled only one request is allowed at the time. Useful for checking that test is working.
    private static final boolean SYNCHRONIZED = false;

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    protected void run(final IAMShieldRunnable... runnables) {
        run(DEFAULT_THREADS, DEFAULT_NUMBER_OF_EXECUTIONS, runnables);
    }

    protected void run(final int numThreads, final int totalNumberOfExecutions, final IAMShieldRunnable... runnables) {
        run(numThreads, totalNumberOfExecutions, this, runnables);
    }


    public static void run(final int numThreads, final int totalNumberOfExecutions, AbstractIAMShieldTest testImpl, final IAMShieldRunnable... runnables) {
        final ExecutorService service = SYNCHRONIZED
                ? Executors.newSingleThreadExecutor()
                : Executors.newFixedThreadPool(numThreads);

        ThreadLocal<IAMShield> iamshields = new ThreadLocal<IAMShield>() {
            @Override
            protected IAMShield initialValue() {
                return IAMShield.getInstance(testImpl.getAuthServerRoot().toString(), "master", "admin", "admin", org.iamshield.models.Constants.ADMIN_CLI_CLIENT_ID, TLSUtils.initializeTLS());
            }
        };

        AtomicInteger currentThreadIndex = new AtomicInteger();
        Collection<Callable<Void>> tasks = new LinkedList<>();
        Collection<Throwable> failures = new ConcurrentLinkedQueue<>();
        final List<Callable<Void>> runnablesToTasks = new LinkedList<>();

        // Track all used admin clients, so they can be closed after the test
        Set<IAMShield> usedIAMShields = Collections.synchronizedSet(new HashSet<>());

        for (IAMShieldRunnable runnable : runnables) {
            runnablesToTasks.add(() -> {
                int arrayIndex = currentThreadIndex.getAndIncrement() % numThreads;
                try {
                    IAMShield iamshield = iamshields.get();
                    usedIAMShields.add(iamshield);

                    runnable.run(arrayIndex % numThreads, iamshield, iamshield.realm(REALM_NAME));
                } catch (Throwable ex) {
                    failures.add(ex);
                }
                return null;
            });
        }
        for (int i = 0; i < totalNumberOfExecutions; i ++) {
            runnablesToTasks.forEach(tasks::add);
        }

        try {
            service.invokeAll(tasks);
            service.shutdown();
            service.awaitTermination(3, TimeUnit.MINUTES);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        } finally {
            for (IAMShield iamshield : usedIAMShields) {
                try {
                    iamshield.close();
                } catch (Exception e) {
                    failures.add(e);
                }
            }
        }

        if (! failures.isEmpty()) {
            RuntimeException ex = new RuntimeException("There were failures in threads. Failures count: " + failures.size());
            failures.forEach(ex::addSuppressed);
            failures.forEach(e -> testImpl.getLogger().error(e.getMessage(), e));
            throw ex;
        }
    }


    public interface IAMShieldRunnable {

        void run(int threadIndex, IAMShield iamshield, RealmResource realm) throws Throwable;

    }

}
