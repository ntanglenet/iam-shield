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
package org.iamshield.services.securityprofile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.jboss.logging.Logger;
import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderConfigurationBuilder;
import org.iamshield.representations.idm.SecurityProfileConfiguration;
import org.iamshield.securityprofile.SecurityProfileProvider;
import org.iamshield.securityprofile.SecurityProfileProviderFactory;
import org.iamshield.services.clientpolicy.ClientPoliciesUtil;
import org.iamshield.services.clientpolicy.ClientPolicyException;
import org.iamshield.util.JsonSerialization;
import org.iamshield.utils.FileUtils;

/**
 * The default implementation for the security profile. It reads the configuration
 * from the file configured.
 * @author rmartinc
 */
public class DefaultSecurityProfileProviderFactory implements SecurityProfileProviderFactory {

    private static final Logger logger = Logger.getLogger(DefaultSecurityProfileProviderFactory.class);

    private String name;
    private volatile SecurityProfileConfiguration configuration;

    @Override
    public SecurityProfileProvider create(IAMShieldSession session) {
        return new DefaultSecurityProfileProvider(readConfiguration(session));
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                    .name("name")
                    .type("string")
                    .helpText("Name for the security configuration file to use. File `name`.json is searched in classapth and `conf` installation folder.")
                    .add()
                .build();
    }

    @Override
    public void init(Config.Scope config) {
        this.name = config.get("name", "none-security-profile");
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return "default";
    }

    protected SecurityProfileConfiguration readConfiguration(IAMShieldSession session) {
        if (configuration == null) {
            synchronized (this) {
                SecurityProfileConfiguration conf;
                final String file = name + ".json";
                try {
                    try (InputStream is = FileUtils.getJsonFileFromClasspathOrConfFolder(file)) {
                        conf = JsonSerialization.readValue(is, SecurityProfileConfiguration.class);
                    }
                    // read the list of client profiles and policies validated
                    conf.setDefaultClientProfiles(ClientPoliciesUtil.readGlobalClientProfilesRepresentation(session, conf.getClientProfiles()));
                    conf.setDefaultClientPolicies(ClientPoliciesUtil.readGlobalClientPoliciesRepresentation(session, conf.getClientPolicies(),
                            conf.getDefaultClientProfiles()));
                } catch (ClientPolicyException|IOException e) {
                    throw new IllegalStateException("Error loading the security profile from file " + file, e);
                }
                this.configuration = conf;
            }
        }
        return this.configuration;
    }
}
