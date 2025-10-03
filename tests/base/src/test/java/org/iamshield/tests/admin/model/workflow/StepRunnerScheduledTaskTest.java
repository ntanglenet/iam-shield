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

package org.iamshield.tests.admin.model.workflow;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.common.util.Time;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserProvider;
import org.iamshield.models.workflow.DisableUserStepProviderFactory;
import org.iamshield.models.workflow.WorkflowStepRunnerSuccessEvent;
import org.iamshield.models.workflow.SetUserAttributeStepProviderFactory;
import org.iamshield.models.workflow.UserCreationTimeWorkflowProviderFactory;
import org.iamshield.provider.ProviderEventListener;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.workflows.WorkflowStepRepresentation;
import org.iamshield.representations.workflows.WorkflowRepresentation;
import org.iamshield.storage.UserStoragePrivateUtil;
import org.iamshield.testframework.annotations.InjectAdminClient;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;

@IAMShieldIntegrationTest(config = WorkflowsScheduledTaskServerConfig.class)
public class StepRunnerScheduledTaskTest {

    private static final String REALM_NAME = "default";

    @InjectRunOnServer(permittedPackages = "org.iamshield.tests")
    RunOnServerClient runOnServer;

    @InjectAdminClient(mode = InjectAdminClient.Mode.BOOTSTRAP)
    IAMShield adminClient;

    @Test
    public void testStepRunnerScheduledTask() {
        for (int i = 0; i < 2; i++) {
            RealmRepresentation realm = new RealmRepresentation();

            realm.setRealm(REALM_NAME.concat("-").concat(String.valueOf(i)));
            realm.setEnabled(true);

            adminClient.realms().create(realm);

            assertStepRuns(realm.getRealm());
        }
    }

    private void assertStepRuns(String realmName) {
        RealmResource realm = adminClient.realm(realmName);

        realm.workflows().create(WorkflowRepresentation.create()
                .of(UserCreationTimeWorkflowProviderFactory.ID)
                .withSteps(
                        WorkflowStepRepresentation.create().of(SetUserAttributeStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .withConfig("message", "message")
                                .build(),
                        WorkflowStepRepresentation.create().of(DisableUserStepProviderFactory.ID)
                                .after(Duration.ofDays(5))
                                .build()
                ).build()).close();

        realm.users().create(UserConfigBuilder.create()
                .username("alice")
                .email("alice@keycloak.org")
                .name("alice", "wonderland")
                .build())
                .close();

        runOnServer.run((session -> {
            IAMShieldSessionFactory sessionFactory = session.getIAMShieldSessionFactory();
            CountDownLatch count = new CountDownLatch(2);

            ProviderEventListener listener = event -> {
                if (event instanceof WorkflowStepRunnerSuccessEvent e) {
                    IAMShieldSession s = e.session();
                    RealmModel r = s.getContext().getRealm();

                    if (!realmName.equals(r.getName())) {
                        return;
                    }

                    UserProvider provider = UserStoragePrivateUtil.userLocalStorage(s);
                    UserModel user = provider.getUserByUsername(r, "alice");
                    if (user.isEnabled() && user.getAttributes().containsKey("message")) {
                        // notified
                        count.countDown();
                        // force execution of next step
                        user.removeAttribute("message");
                        Time.setOffset(Math.toIntExact(Duration.ofDays(20).toSeconds()));
                    } else if (!user.isEnabled()) {
                        // disabled
                        count.countDown();
                    }
                }
            };

            try {
                sessionFactory.register(listener);
                Time.setOffset(Math.toIntExact(Duration.ofDays(12).toSeconds()));
                System.out.println("Waiting for steps to be run for realm " + realmName);
                assertTrue(count.await(15, TimeUnit.SECONDS));
                System.out.println("... steps run for realm " + realmName);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            } finally {
                sessionFactory.unregister(listener);
                Time.setOffset(0);
            }
        }));
    }
}
