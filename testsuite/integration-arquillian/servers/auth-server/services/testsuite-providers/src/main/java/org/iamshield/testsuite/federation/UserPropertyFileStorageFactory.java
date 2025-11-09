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
package org.iamshield.testsuite.federation;

import java.io.File;
import java.io.FileInputStream;
import org.iamshield.Config;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.storage.UserStorageProviderFactory;
import org.iamshield.storage.UserStorageProviderModel;
import org.iamshield.storage.user.ImportSynchronization;
import org.iamshield.storage.user.SynchronizationResult;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import org.iamshield.common.util.EnvUtil;
import org.iamshield.component.ComponentValidationException;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.ProviderConfigurationBuilder;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UserPropertyFileStorageFactory implements UserStorageProviderFactory<UserPropertyFileStorage>, ImportSynchronization {

    public static final String PROVIDER_ID = "user-password-props-arq";
    public static final String PROPERTY_FILE = "propertyFile";

    public static final String VALIDATION_PROP_FILE_NOT_CONFIGURED = "user property file is not configured";
    public static final String VALIDATION_PROP_FILE_DOESNT_EXIST = "user property file does not exist";

    protected static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property().name(PROPERTY_FILE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Property File")
                .helpText("File that contains name value pairs")
                .defaultValue(null)
                .add()
                .property().name("federatedStorage")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("User Federated Storage")
                .helpText("User Federated Storage")
                .defaultValue(null)
                .add()
                .build();
    }

    @Override
    public void validateConfiguration(IAMShieldSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        String fp = config.getConfig().getFirst(PROPERTY_FILE);
        if (fp == null) {
            throw new ComponentValidationException(VALIDATION_PROP_FILE_NOT_CONFIGURED);
        }
        fp = EnvUtil.replace(fp);
        File file = new File(fp);
        if (!file.exists()) {
            throw new ComponentValidationException(VALIDATION_PROP_FILE_DOESNT_EXIST);
        }
    }

    @Override
    public UserPropertyFileStorage create(IAMShieldSession session, ComponentModel model) {
        String path = model.getConfig().getFirst(PROPERTY_FILE);
        path = EnvUtil.replace(path);

        Properties props = new Properties();
        try (InputStream is = new FileInputStream(path)) {
            props.load(is);
            is.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return new UserPropertyFileStorage(session, model, props);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public SynchronizationResult sync(IAMShieldSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        return SynchronizationResult.ignored();
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, IAMShieldSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        return SynchronizationResult.ignored();
    }

}
