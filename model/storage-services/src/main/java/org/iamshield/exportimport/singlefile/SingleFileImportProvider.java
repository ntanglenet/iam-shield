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

package org.iamshield.exportimport.singlefile;

import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.exportimport.AbstractFileBasedImportProvider;
import org.iamshield.exportimport.Strategy;
import org.iamshield.exportimport.util.ExportImportSessionTask;
import org.iamshield.exportimport.util.ImportUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.util.JsonSerialization;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SingleFileImportProvider extends AbstractFileBasedImportProvider {

    private static final Logger logger = Logger.getLogger(SingleFileImportProvider.class);
    private final IAMShieldSessionFactory factory;

    private final File file;
    private final Strategy strategy;

    // Allows to cache representation per provider to avoid parsing them twice
    protected Map<String, RealmRepresentation> realmReps;

    public SingleFileImportProvider(IAMShieldSessionFactory factory, File file, Strategy strategy) {
        this.factory = factory;
        this.file = file;
        this.strategy = strategy;
    }

    @Override
    public void importModel() throws IOException {
        logger.infof("Full importing from file %s", this.file.getAbsolutePath());
        checkRealmReps();

        new ExportImportSessionTask() {

            @Override
            protected void runExportImportTask(IAMShieldSession session) {
                ImportUtils.importRealms(session, realmReps.values(), strategy);
            }

        }.runTask(factory);
    }

    @Override
    public boolean isMasterRealmExported() throws IOException {
        checkRealmReps();
        return (realmReps.containsKey(Config.getAdminRealm()));
    }

    protected void checkRealmReps() throws IOException {
        if (realmReps == null) {
            InputStream is = parseFile(file);
            realmReps = ImportUtils.getRealmsFromStream(JsonSerialization.mapper, is);
        }
    }

    @Override
    public void close() {

    }
}
