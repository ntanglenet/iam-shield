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

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel.RealmRemovedEvent;
import org.iamshield.models.UserModel.UserRemovedEvent;

public class JpaWorkflowStateProviderFactory implements WorkflowStateProviderFactory {

    public static final String PROVIDER_ID = "jpa";

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        factory.register(fired -> {
            if (fired instanceof UserRemovedEvent event) {
                onUserRemovedEvent(event);
            } if (fired instanceof RealmRemovedEvent event) {
                onRealmRemovedEvent(event);
            }
        });
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public WorkflowStateProvider create(IAMShieldSession session) {
        return new JpaWorkflowStateProvider(session);
    }

    @Override
    public void close() {
    }

    private void onRealmRemovedEvent(RealmRemovedEvent event) {
        IAMShieldSession session = event.getIAMShieldSession();
        WorkflowStateProvider provider = session.getProvider(WorkflowStateProvider.class);
        provider.removeAll();
    }

    private void onUserRemovedEvent(UserRemovedEvent event) {
        IAMShieldSession session = event.getIAMShieldSession();
        WorkflowStateProvider provider = session.getProvider(WorkflowStateProvider.class);
        provider.removeByResource(event.getUser().getId());
    }
}
