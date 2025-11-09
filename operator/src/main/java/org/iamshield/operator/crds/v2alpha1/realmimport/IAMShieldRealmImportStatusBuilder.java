/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.operator.crds.v2alpha1.realmimport;

import java.util.ArrayList;
import java.util.List;

public class IAMShieldRealmImportStatusBuilder {
    private final KeycloakRealmImportStatusCondition readyCondition;
    private final KeycloakRealmImportStatusCondition startedCondition;
    private final KeycloakRealmImportStatusCondition hasErrorsCondition;

    private final List<String> notReadyMessages = new ArrayList<>();
    private final List<String> startedMessages = new ArrayList<>();
    private final List<String> errorMessages = new ArrayList<>();

    public IAMShieldRealmImportStatusBuilder() {
        readyCondition = new IAMShieldRealmImportStatusCondition();
        readyCondition.setType(KeycloakRealmImportStatusCondition.DONE);
        readyCondition.setStatus(false);

        startedCondition = new IAMShieldRealmImportStatusCondition();
        startedCondition.setType(KeycloakRealmImportStatusCondition.STARTED);
        startedCondition.setStatus(false);

        hasErrorsCondition = new IAMShieldRealmImportStatusCondition();
        hasErrorsCondition.setType(KeycloakRealmImportStatusCondition.HAS_ERRORS);
        hasErrorsCondition.setStatus(false);
    }

    public IAMShieldRealmImportStatusBuilder addStartedMessage(String message) {
        startedCondition.setStatus(true);
        readyCondition.setStatus(false);
        hasErrorsCondition.setStatus(false);
        startedMessages.add(message);
        return this;
    }

    public IAMShieldRealmImportStatusBuilder addDone() {
        startedCondition.setStatus(false);
        readyCondition.setStatus(true);
        hasErrorsCondition.setStatus(false);
        return this;
    }

    public IAMShieldRealmImportStatusBuilder addNotReadyMessage(String message) {
        startedCondition.setStatus(false);
        readyCondition.setStatus(false);
        hasErrorsCondition.setStatus(false);
        notReadyMessages.add(message);
        return this;
    }

    public IAMShieldRealmImportStatusBuilder addErrorMessage(String message) {
        startedCondition.setStatus(false);
        readyCondition.setStatus(false);
        hasErrorsCondition.setStatus(true);
        errorMessages.add(message);
        return this;
    }

    public IAMShieldRealmImportStatus build() {
        readyCondition.setMessage(String.join("\n", notReadyMessages));
        startedCondition.setMessage(String.join("\n", startedMessages));
        hasErrorsCondition.setMessage(String.join("\n", errorMessages));

        KeycloakRealmImportStatus status = new IAMShieldRealmImportStatus();
        status.setConditions(List.of(readyCondition, startedCondition, hasErrorsCondition));
        return status;
    }
}
