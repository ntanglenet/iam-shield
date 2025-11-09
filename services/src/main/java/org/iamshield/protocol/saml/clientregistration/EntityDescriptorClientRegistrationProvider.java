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

package org.iamshield.protocol.saml.clientregistration;

import org.iamshield.exportimport.ClientDescriptionConverter;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.protocol.saml.EntityDescriptorDescriptionConverter;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.services.clientregistration.AbstractClientRegistrationProvider;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class EntityDescriptorClientRegistrationProvider extends AbstractClientRegistrationProvider {

    public EntityDescriptorClientRegistrationProvider(IAMShieldSession session) {
        super(session);
    }

    @POST
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createSaml(String descriptor) {
        ClientRepresentation client = session.getProvider(ClientDescriptionConverter.class, EntityDescriptorDescriptionConverter.ID).convertToInternal(descriptor);
        EntityDescriptorClientRegistrationContext context = new EntityDescriptorClientRegistrationContext(session, client, this);
        client = create(context);
        validateClient(client, true);
        URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(client.getClientId()).build();
        return Response.created(uri).entity(client).build();
    }



}
