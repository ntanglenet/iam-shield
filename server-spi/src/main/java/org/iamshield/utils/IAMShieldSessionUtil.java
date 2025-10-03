/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.utils;

import org.iamshield.common.util.Resteasy;
import org.iamshield.models.IAMShieldContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;

public class IAMShieldSessionUtil {

    private static final String NO_REALM = "no_realm_found_in_session";

    private IAMShieldSessionUtil() {

    }

    /**
     * Get the {@link IAMShieldSession} currently associated with the thread.
     *
     * @return the current session
     */
    public static IAMShieldSession getIAMShieldSession() {
        return Resteasy.getContextData(IAMShieldSession.class);
    }

    /**
     * Associate the {@link IAMShieldSession} with the current thread.
     * <br>Warning: should not be called directly. Keycloak will manage this.
     *
     * @param session
     * @return the existing {@link IAMShieldSession} or null
     */
    public static IAMShieldSession setIAMShieldSession(IAMShieldSession session) {
        return Resteasy.pushContext(IAMShieldSession.class, session);
    }

    public static String getRealmNameFromContext(IAMShieldSession session) {
        if(session == null) {
            return NO_REALM;
        }

        IAMShieldContext context = session.getContext();
        if(context == null) {
            return NO_REALM;
        }

        RealmModel realm = context.getRealm();
        if (realm == null) {
            return NO_REALM;
        }

        if(realm.getName() != null) {
            return realm.getName();
        } else {
            return NO_REALM;
        }
    }

}
