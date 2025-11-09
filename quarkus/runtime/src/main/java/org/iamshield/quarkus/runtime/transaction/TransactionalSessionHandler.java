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

package org.iamshield.quarkus.runtime.transaction;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.quarkus.runtime.integration.QuarkusIAMShieldSessionFactory;

/**
 * <p>A {@link TransactionalSessionHandler} is responsible for managing transaction sessions and its lifecycle. Its subtypes
 * are usually related to components available from the underlying stack that runs on top of the request processing chain
 * as well as at the end in order to create transaction sessions and close them accordingly, respectively.
 */
public interface TransactionalSessionHandler {

    /**
     * Creates a {@link IAMShieldSession}.
     *
     * @return a keycloak session
     */
    default IAMShieldSession create() {
        IAMShieldSessionFactory sessionFactory = QuarkusIAMShieldSessionFactory.getInstance();
        return sessionFactory.create();
    }

    /**
     * begin a transaction if possible
     *
     * @param session a session
     */
    default void beginTransaction(IAMShieldSession session) {
        session.getTransactionManager().begin();
    }

    /**
     * Closes a {@link IAMShieldSession}.
     *
     * @param session a session
     */
    default void close(IAMShieldSession session) {
        if (session == null || session.isClosed()) {
            return;
        }

        session.close();
    }
}
