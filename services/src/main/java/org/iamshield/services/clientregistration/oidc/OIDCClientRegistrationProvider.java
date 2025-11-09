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
package org.iamshield.services.clientregistration.oidc;

import org.jboss.logging.Logger;
import org.iamshield.common.util.Time;
import org.iamshield.models.ClientModel;
import org.iamshield.models.ClientSecretConstants;
import org.iamshield.models.IAMShieldContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.utils.ModelToRepresentation;
import org.iamshield.models.utils.RepresentationToModel;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.protocol.oidc.mappers.AbstractPairwiseSubMapper;
import org.iamshield.protocol.oidc.mappers.PairwiseSubMapperHelper;
import org.iamshield.protocol.oidc.mappers.SHA256PairwiseSubMapper;
import org.iamshield.protocol.oidc.utils.SubjectType;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;
import org.iamshield.representations.oidc.OIDCClientRepresentation;
import org.iamshield.services.ErrorResponseException;
import org.iamshield.services.ServicesLogger;
import org.iamshield.services.Urls;
import org.iamshield.services.clientregistration.AbstractClientRegistrationProvider;
import org.iamshield.services.clientregistration.ClientRegistrationException;
import org.iamshield.services.clientregistration.ErrorCodes;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.iamshield.urls.UrlType;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class OIDCClientRegistrationProvider extends AbstractClientRegistrationProvider {

    private static final Logger logger = Logger.getLogger(OIDCClientRegistrationProvider.class);

    public OIDCClientRegistrationProvider(IAMShieldSession session) {
        super(session);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createOIDC(OIDCClientRepresentation clientOIDC) {
        if (clientOIDC.getClientId() != null) {
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client Identifier included", Response.Status.BAD_REQUEST);
        }

        try {
            ClientRepresentation client = DescriptionConverter.toInternal(session, clientOIDC);

            OIDCClientRegistrationContext oidcContext = new OIDCClientRegistrationContext(session, client, this, clientOIDC);
            client = create(oidcContext);

            ClientModel clientModel = session.getContext().getRealm().getClientByClientId(client.getClientId());
            updatePairwiseSubMappers(clientModel, SubjectType.parse(clientOIDC.getSubjectType()), clientOIDC.getSectorIdentifierUri());
            updateClientRepWithProtocolMappers(clientModel, client);

            validateClient(clientModel, clientOIDC, true);

            URI uri = getRegistrationClientUri(clientModel);
            clientOIDC = DescriptionConverter.toExternalResponse(session, client, uri);
            clientOIDC.setClientIdIssuedAt(Time.currentTime());
            return Response.created(uri).entity(clientOIDC).build();
        } catch (ClientRegistrationException cre) {
            ServicesLogger.LOGGER.clientRegistrationException(cre.getMessage());
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client metadata invalid", Response.Status.BAD_REQUEST);
        }
    }

    @GET
    @Path("{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOIDC(@PathParam("clientId") String clientId) {
        ClientModel client = session.getContext().getRealm().getClientByClientId(clientId);

        ClientRepresentation clientRepresentation = get(client);

        OIDCClientRepresentation clientOIDC = DescriptionConverter.toExternalResponse(session, clientRepresentation, getRegistrationClientUri(client));
        return Response.ok(clientOIDC).build();
    }

    @PUT
    @Path("{clientId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateOIDC(@PathParam("clientId") String clientId, OIDCClientRepresentation clientOIDC) {
        try {
            ClientRepresentation client = DescriptionConverter.toInternal(session, clientOIDC);

            if (clientOIDC.getScope() != null) {
                ClientModel oldClient = session.getContext().getRealm().getClientById(clientOIDC.getClientId());
                Collection<String> defaultClientScopes = oldClient.getClientScopes(true).keySet();
                client.setDefaultClientScopes(new ArrayList<>(defaultClientScopes));
            }

            OIDCClientRegistrationContext oidcContext = new OIDCClientRegistrationContext(session, client, this, clientOIDC);
            client = update(clientId, oidcContext);

            ClientModel clientModel = session.getContext().getRealm().getClientByClientId(client.getClientId());
            updatePairwiseSubMappers(clientModel, SubjectType.parse(clientOIDC.getSubjectType()), clientOIDC.getSectorIdentifierUri());
            updateClientRepWithProtocolMappers(clientModel, client);

            client.setSecret(clientModel.getSecret());
            client.getAttributes().put(ClientSecretConstants.CLIENT_SECRET_EXPIRATION,clientModel.getAttribute(ClientSecretConstants.CLIENT_SECRET_EXPIRATION));
            client.getAttributes().put(ClientSecretConstants.CLIENT_SECRET_CREATION_TIME,clientModel.getAttribute(ClientSecretConstants.CLIENT_SECRET_CREATION_TIME));

            validateClient(clientModel, clientOIDC, false);

            URI uri = getRegistrationClientUri(clientModel);
            clientOIDC = DescriptionConverter.toExternalResponse(session, client, uri);
            return Response.ok(clientOIDC).build();
        } catch (ClientRegistrationException cre) {
            ServicesLogger.LOGGER.clientRegistrationException(cre.getMessage());
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client metadata invalid", Response.Status.BAD_REQUEST);
        }
    }

    @DELETE
    @Path("{clientId}")
    public void deleteOIDC(@PathParam("clientId") String clientId) {
        delete(clientId);
    }

    private void updatePairwiseSubMappers(ClientModel clientModel, SubjectType subjectType, String sectorIdentifierUri) {
        if (subjectType == SubjectType.PAIRWISE) {

            // See if we have existing pairwise mapper and update it. Otherwise create new
            AtomicBoolean foundPairwise = new AtomicBoolean(false);

            clientModel.getProtocolMappersStream().filter((ProtocolMapperModel mapping) -> {
                if (mapping.getProtocolMapper().endsWith(AbstractPairwiseSubMapper.PROVIDER_ID_SUFFIX)) {
                    foundPairwise.set(true);
                    return true;
                } else {
                    return false;
                }
            }).collect(Collectors.toList()).forEach((ProtocolMapperModel mapping) -> {
                PairwiseSubMapperHelper.setSectorIdentifierUri(mapping, sectorIdentifierUri);
                clientModel.updateProtocolMapper(mapping);
            });

            // We don't have existing pairwise mapper. So create new
            if (!foundPairwise.get()) {
                ProtocolMapperRepresentation newPairwise = SHA256PairwiseSubMapper.createPairwiseMapper(sectorIdentifierUri, null);
                clientModel.addProtocolMapper(RepresentationToModel.toModel(newPairwise));
            }

        } else {
            // Rather find and remove all pairwise mappers
            clientModel.getProtocolMappersStream()
                    .filter(mapperRep -> mapperRep.getProtocolMapper().endsWith(AbstractPairwiseSubMapper.PROVIDER_ID_SUFFIX))
                    .collect(Collectors.toList())
                    .forEach(clientModel::removeProtocolMapper);
        }
    }

    private void updateClientRepWithProtocolMappers(ClientModel clientModel, ClientRepresentation rep) {
        List<ProtocolMapperRepresentation> mappings =
                clientModel.getProtocolMappersStream().map(ModelToRepresentation::toRepresentation).collect(Collectors.toList());
        rep.setProtocolMappers(mappings);
    }

    private URI getRegistrationClientUri(ClientModel client) {
        IAMShieldContext context = session.getContext();
        RealmModel realm = context.getRealm();
        URI backendUri = context.getUri(UrlType.BACKEND).getBaseUri();
        return Urls.clientRegistration(backendUri, realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL, client.getClientId());
    }
}
