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

package org.iamshield.protocol.oidc;

import org.iamshield.exportimport.ClientDescriptionConverter;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.oidc.OIDCClientRepresentation;
import org.iamshield.services.clientregistration.oidc.DescriptionConverter;
import org.iamshield.util.JsonSerialization;

import java.io.IOException;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class OIDCClientDescriptionConverter implements ClientDescriptionConverter {

    private final IAMShieldSession session;

    public OIDCClientDescriptionConverter(IAMShieldSession session) {
        this.session = session;
    }


    @Override
    public ClientRepresentation convertToInternal(String description) {
        try {
            OIDCClientRepresentation clientOIDC = JsonSerialization.readValue(description, OIDCClientRepresentation.class);
            return DescriptionConverter.toInternal(session, clientOIDC);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close() {
    }


}
