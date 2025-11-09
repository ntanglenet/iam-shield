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

import static org.iamshield.models.workflow.ResourceOperationType.toOperationType;

import org.iamshield.events.Event;
import org.iamshield.events.EventType;
import org.iamshield.events.admin.AdminEvent;
import org.iamshield.events.admin.OperationType;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.provider.ProviderEvent;

import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;

public enum ResourceType {

    USERS(
            org.iamshield.events.admin.ResourceType.USER,
            List.of(OperationType.CREATE),
            List.of(EventType.LOGIN, EventType.REGISTER),
            (session, id) -> session.users().getUserById(session.getContext().getRealm(), id)
    );

    private final org.iamshield.events.admin.ResourceType supportedAdminResourceType;
    private final List<OperationType> supportedAdminOperationTypes;
    private final List<EventType> supportedEventTypes;
    private final BiFunction<IAMShieldSession, String, ?> resourceResolver;

    ResourceType(org.iamshield.events.admin.ResourceType supportedAdminResourceType,
                 List<OperationType> supportedAdminOperationTypes,
                 List<EventType> supportedEventTypes,
                 BiFunction<IAMShieldSession, String, ?> resourceResolver) {
        this.supportedAdminResourceType = supportedAdminResourceType;
        this.supportedAdminOperationTypes = supportedAdminOperationTypes;
        this.supportedEventTypes = supportedEventTypes;
        this.resourceResolver = resourceResolver;
    }

    public WorkflowEvent toEvent(AdminEvent event) {
        if (Objects.equals(this.supportedAdminResourceType, event.getResourceType())
                && this.supportedAdminOperationTypes.contains(event.getOperationType())) {

            ResourceOperationType resourceOperationType = toOperationType(event.getOperationType());
            if (resourceOperationType != null) {
                return new WorkflowEvent(this, resourceOperationType, event.getResourceId(), event);
            }
        }
        return null;
    }

    public WorkflowEvent toEvent(Event event) {
        if (this.supportedEventTypes.contains(event.getType())) {
            ResourceOperationType resourceOperationType = toOperationType(event.getType());
            String resourceId = switch (this) {
                case USERS -> event.getUserId();
            };
            if (resourceOperationType != null && resourceId != null) {
                return new WorkflowEvent(this, resourceOperationType, event.getUserId(), event);
            }
        }
        return null;
    }

    public WorkflowEvent toEvent(ProviderEvent event) {
        ResourceOperationType resourceOperationType = toOperationType(event.getClass());

        if (resourceOperationType == null) {
            return null;
        }

        String resourceId = resourceOperationType.getResourceId(event);

        if (resourceId == null) {
            return null;
        }

        return new WorkflowEvent(this, resourceOperationType, resourceId, event);
    }

    public Object resolveResource(IAMShieldSession session, String id) {
        return resourceResolver.apply(session, id);
    }
}
