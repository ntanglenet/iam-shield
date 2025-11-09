/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */

package org.iamshield.models.workflow;

import org.iamshield.events.Event;
import org.iamshield.events.EventListenerProvider;
import org.iamshield.events.admin.AdminEvent;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.ProviderEvent;
import org.iamshield.provider.ProviderEventListener;

public class WorkflowEventListener implements EventListenerProvider, ProviderEventListener {

    private final IAMShieldSession session;

    public WorkflowEventListener(IAMShieldSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        WorkflowEvent workflowEvent = ResourceType.USERS.toEvent(event);
        trySchedule(workflowEvent);
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        WorkflowEvent workflowEvent = ResourceType.USERS.toEvent(event);
        trySchedule(workflowEvent);
    }

    @Override
    public void onEvent(ProviderEvent event) {
        RealmModel realm = session.getContext().getRealm();

        if (realm == null) {
            return;
        }

        trySchedule(ResourceType.USERS.toEvent(event));
    }

    private void trySchedule(WorkflowEvent event) {
        if (event != null) {
            WorkflowsManager manager = new WorkflowsManager(session);
            manager.processEvent(event);
        }
    }

    @Override
    public void close() {

    }
}
