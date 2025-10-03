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

package org.iamshield.protocol.oid4vc.issuance.credentialbuilder;

import java.util.ArrayList;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.protocol.oid4vc.model.Format;
import org.iamshield.provider.ProviderConfigProperty;

import java.util.List;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class LDCredentialBuilderFactory implements CredentialBuilderFactory {

    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public String getSupportedFormat() {
        return Format.LDP_VC;
    }

    @Override
    public String getHelpText() {
        return "Builds verifiable credentials on the LDP-VC format (https://www.w3.org/TR/vc-data-model).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public CredentialBuilder create(IAMShieldSession session, ComponentModel model) {
        return new LDCredentialBuilder();
    }
}
