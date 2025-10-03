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

package org.iamshield.models.workflow;

import java.time.Duration;

import org.iamshield.Config.Scope;
import org.iamshield.common.Profile;
import org.iamshield.events.EventListenerProvider;
import org.iamshield.events.EventListenerProviderFactory;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.services.scheduled.ClusterAwareScheduledTaskRunner;
import org.iamshield.timer.TimerProvider;
import org.iamshield.provider.ProviderEvent;

public class WorkflowsEventListenerFactory implements EventListenerProviderFactory, EnvironmentDependentProviderFactory {

    public static final String ID = "workflow-event-listener";
    private static final long DEFAULT_STEP_RUNNER_TASK_INTERVAL = Duration.ofHours(12).toMillis();
    private long stepRunnerTaskInterval;

    @Override
    public EventListenerProvider create(IAMShieldSession session) {
        return new WorkflowEventListener(session);
    }

    @Override
    public boolean isGlobal() {
        return true;
    }

    @Override
    public void init(Scope config) {
        stepRunnerTaskInterval = config.getLong("stepRunnerTaskInterval", DEFAULT_STEP_RUNNER_TASK_INTERVAL);
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        factory.register(event -> {
            IAMShieldSession session = event.getIAMShieldSession();

            if (session != null) {
                onEvent(event, session);
            }
        });
        scheduleStepRunnerTask(factory);
    }

    private void onEvent(ProviderEvent event, IAMShieldSession session) {
        WorkflowEventListener provider = (WorkflowEventListener) session.getProvider(EventListenerProvider.class, getId());
        provider.onEvent(event);
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public boolean isSupported(Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.WORKFLOWS);
    }

    private void scheduleStepRunnerTask(IAMShieldSessionFactory factory) {
        try (IAMShieldSession session = factory.create()) {
            TimerProvider timer = session.getProvider(TimerProvider.class);
            timer.schedule(new ClusterAwareScheduledTaskRunner(factory, new WorkflowRunnerScheduledTask(factory), stepRunnerTaskInterval), stepRunnerTaskInterval);
        }
    }
}
