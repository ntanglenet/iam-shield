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

package org.iamshield.protocol.saml.mappers;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.ProtocolMapper;
import org.iamshield.protocol.saml.SamlProtocol;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class AbstractSAMLProtocolMapper implements ProtocolMapper {


    @Override
    public String getProtocol() {
        return SamlProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public void close() {

    }

    @Override
    public final ProtocolMapper create(IAMShieldSession session) {
        throw new RuntimeException("UNSUPPORTED METHOD");
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {

    }
}
