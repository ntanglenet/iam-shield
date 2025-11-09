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
import org.iamshield.common.Profile;
import org.iamshield.component.ComponentFactory;
import org.iamshield.provider.EnvironmentDependentProviderFactory;

public interface WorkflowStepProviderFactory<P extends WorkflowStepProvider> extends ComponentFactory<P, WorkflowStepProvider>, EnvironmentDependentProviderFactory {

    ResourceType getType();

    @Override
    default boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.WORKFLOWS);
    }
}
