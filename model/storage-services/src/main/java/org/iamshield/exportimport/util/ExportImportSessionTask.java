/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.exportimport.util;

import java.io.IOException;

import org.iamshield.connections.jpa.support.EntityManagers;
import org.iamshield.exportimport.ExportImportConfig;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.utils.IAMShieldSessionUtil;

/**
 * Just to wrap {@link IOException}
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class ExportImportSessionTask {

    public enum Mode {
        BATCHED, // turn on batched optimizations - good for read-only and bulk inserts, and flush / clear when done
        NORMAL
    }

    public void runTask(IAMShieldSessionFactory factory) {
        runTask(factory, Mode.NORMAL);
    }

    public void runTask(IAMShieldSessionFactory factory, Mode mode) {
        boolean useExistingSession = ExportImportConfig.isSingleTransaction();
        IAMShieldSession existing = IAMShieldSessionUtil.getIAMShieldSession();
        if (useExistingSession && existing != null && existing.getTransactionManager().isActive()) {
            run(mode, existing);
        } else {
            IAMShieldModelUtils.runJobInTransaction(factory, session -> this.run(mode, session));
        }
    }

    private void run(Mode mode, IAMShieldSession session) {
        Runnable task = () -> {
            try {
                runExportImportTask(session);
            } catch (IOException ioe) {
                throw new RuntimeException("Error during export/import: " + ioe.getMessage(), ioe);
            }
        };
        if (mode == Mode.BATCHED) {
            EntityManagers.runInBatch(session, task, true);
        } else {
            task.run();
        }
    }

    protected abstract void runExportImportTask(IAMShieldSession session) throws IOException;
}
