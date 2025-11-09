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

import org.iamshield.Config;
import org.iamshield.exportimport.ExportImportConfig;
import org.iamshield.exportimport.ExportProvider;
import org.iamshield.exportimport.ExportProviderFactory;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;

import java.io.File;
import java.util.List;
import java.util.Objects;

/**
 * Construct a {@link SingleFileExportProvider} to be used to export one or more realms.
 * For the sake of testing in the legacy testing setup, configurations can be overwritten via system properties.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SingleFileExportProviderFactory implements ExportProviderFactory {

    public static final String PROVIDER_ID = "singleFile";
    public static final String FILE = "file";
    public static final String REALM_NAME = "realmName";
    private Config.Scope config;

    @Override
    public ExportProvider create(IAMShieldSession session) {
        String fileName = System.getProperty(ExportImportConfig.FILE, config.get(FILE));
        Objects.requireNonNull(fileName, "file name not configured");
        String realmName = System.getProperty(ExportImportConfig.REALM_NAME, config.get(REALM_NAME));
        return new SingleFileExportProvider(session.getIAMShieldSessionFactory()).withFile(new File(fileName)).withRealmName(realmName);
    }

    @Override
    public void init(Config.Scope config) {
        this.config = config;
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(REALM_NAME)
                .type("string")
                .helpText("Realm to export")
                .add()

                .property()
                .name(FILE)
                .type("string")
                .helpText("File to export to")
                .add()

                .build();
    }

}
