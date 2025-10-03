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

package org.iamshield.authentication.requiredactions.util;

import org.iamshield.authentication.RequiredActionProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

import java.util.List;

public class RequiredActionsValidator {
    /**
     * Validate provided required actions
     *
     * @param session         the {@code IAMShieldSession}
     * @param requiredActions IDs of tested required actions
     */
    public static boolean validRequiredActions(IAMShieldSession session, List<String> requiredActions) {
        final IAMShieldSessionFactory sessionFactory = session.getIAMShieldSessionFactory();

        for (String action : requiredActions) {
            if (sessionFactory.getProviderFactory(RequiredActionProvider.class, action) == null) {
                return false;
            }
        }
        return true;
    }
}
