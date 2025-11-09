/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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
package org.iamshield.services.resources.account.resources;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Link;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.iamshield.http.HttpRequest;
import org.iamshield.authorization.model.PermissionTicket;
import org.iamshield.authorization.store.PermissionTicketStore;
import org.iamshield.common.util.IAMShieldUriBuilder;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserModel;
import org.iamshield.services.managers.Auth;
import org.iamshield.utils.MediaType;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourcesService extends AbstractResourceService {

    public ResourcesService(IAMShieldSession session, UserModel user, Auth auth, HttpRequest request) {
        super(session, user, auth, request);
    }

    /**
     * Returns a list of {@link Resource} where the {@link #user} is the resource owner.
     *
     * @param first the first result
     * @param max   the max result
     * @return a list of {@link Resource} where the {@link #user} is the resource owner
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getResources(@QueryParam("name") String name,
            @QueryParam("first") Integer first,
            @QueryParam("max") Integer max) {
        Map<org.iamshield.authorization.model.Resource.FilterOption, String[]> filters =
                new EnumMap<>(org.iamshield.authorization.model.Resource.FilterOption.class);

        filters.put(org.iamshield.authorization.model.Resource.FilterOption.OWNER, new String[] { user.getId() });

        if (name != null) {
            filters.put(org.iamshield.authorization.model.Resource.FilterOption.NAME, new String[] { name });
        }

        return queryResponse((f, m) -> resourceStore.find(null, filters, f, m).stream()
                .map(resource -> new Resource(resource, user, provider)), first, max);
    }

    /**
     * Returns a list of {@link Resource} shared with the {@link #user}
     *
     * @param first the first result
     * @param max the max result
     * @return a list of {@link Resource} shared with the {@link #user}
     */
    @GET
    @Path("shared-with-me")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSharedWithMe(@QueryParam("name") String name,
            @QueryParam("first") Integer first,
            @QueryParam("max") Integer max) {
        return queryResponse((f, m) -> toPermissions(ticketStore.findGrantedResources(auth.getUser().getId(), name, f, m), false)
                .stream(), first, max);
    }

    /**
     * Returns a list of {@link Resource} where the {@link #user} is the resource owner and the resource is 
     * shared with other users.
     *
     * @param first the first result
     * @param max the max result
     * @return a list of {@link Resource} where the {@link #user} is the resource owner and the resource is 
     *      * shared with other users
     */
    @GET
    @Path("shared-with-others")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSharedWithOthers(@QueryParam("first") Integer first, @QueryParam("max") Integer max) {
        return queryResponse(
                (f, m) -> toPermissions(ticketStore.findGrantedOwnerResources(auth.getUser().getId(), f, m), true)
                        .stream(), first, max);
    }

    /**
     */
    @GET
    @Path("pending-requests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPendingRequests() {
        Map<PermissionTicket.FilterOption, String> filters = new EnumMap<>(PermissionTicket.FilterOption.class);

        filters.put(PermissionTicket.FilterOption.REQUESTER, user.getId());
        filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.FALSE.toString());

        final List<PermissionTicket> permissionTickets = ticketStore.find(null, filters, null, null);

        final List<ResourcePermission> resourceList = new ArrayList<>(permissionTickets.size());
        for (PermissionTicket ticket : permissionTickets) {
            ResourcePermission resourcePermission = new ResourcePermission(ticket.getResource(), provider);
            resourcePermission.addScope(new Scope(ticket.getScope()));
            resourceList.add(resourcePermission);
        }

        return queryResponse(
                (f, m) -> resourceList.stream(), -1, resourceList.size());
    }

    @Path("{id}")
    public Object getResource(@PathParam("id") String id) {
        org.iamshield.authorization.model.Resource resource = resourceStore.findById(null, id);

        if (resource == null) {
            throw new NotFoundException("resource_not_found");
        }

        if (!resource.getOwner().equals(user.getId())) {
            throw new BadRequestException("invalid_resource");
        }
        
        return new ResourceService(resource, provider.getIAMShieldSession(), user, auth, request);
    }

    private Collection<ResourcePermission> toPermissions(List<org.iamshield.authorization.model.Resource> resources, boolean withRequesters) {
        Collection<ResourcePermission> permissions = new ArrayList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (org.iamshield.authorization.model.Resource resource : resources) {
            ResourcePermission permission = new ResourcePermission(resource, provider);

            List<PermissionTicket> tickets;

            if (withRequesters) {
                Map<PermissionTicket.FilterOption, String> filters = new EnumMap<>(PermissionTicket.FilterOption.class);

                filters.put(PermissionTicket.FilterOption.OWNER, user.getId());
                filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.TRUE.toString());
                filters.put(PermissionTicket.FilterOption.RESOURCE_ID, resource.getId());

                tickets = ticketStore.find(resource.getResourceServer(), filters, null, null);
            } else {
                tickets = ticketStore.findGranted(resource.getResourceServer(), resource.getName(), user.getId());
            }

            for (PermissionTicket ticket : tickets) {
                if (resource.equals(ticket.getResource())) {
                    if (withRequesters) {
                        Permission user = permission.getPermission(ticket.getRequester());

                        if (user == null) {
                            permission.addPermission(ticket.getRequester(),
                                    user = new Permission(ticket.getRequester(), provider));
                        }

                        user.addScope(ticket.getScope().getName());
                    } else {
                        permission.addScope(new Scope(ticket.getScope()));
                    }
                }
            }

            permissions.add(permission);
        }

        return permissions;
    }
    
    private Response queryResponse(BiFunction<Integer, Integer, Stream<?>> query, Integer first, Integer max) {
        if (first != null && max != null) {
            List result = query.apply(first, max + 1).collect(Collectors.toList());
            int size = result.size();

            if (size > max) {
                result = result.subList(0, size - 1);
            }

            return Response.ok().entity(result).links(createPageLinks(first, max, size)).build();
        }

        return Response.ok().entity(query.apply(-1, -1).collect(Collectors.toList())).build();
    }

    private Link[] createPageLinks(Integer first, Integer max, int resultSize) {
        if (resultSize == 0 || (first == 0 && resultSize <= max)) {
            return new Link[] {};
        }

        List<Link> links = new ArrayList();
        boolean nextPage = resultSize > max;

        if (nextPage) {
            links.add(Link.fromUri(
                    IAMShieldUriBuilder.fromUri(uriInfo.getRequestUri()).replaceQuery("first={first}&max={max}")
                            .build(first + max, max))
                    .rel("next").build());
        }

        if (first > 0) {
            links.add(Link.fromUri(
                    IAMShieldUriBuilder.fromUri(uriInfo.getRequestUri()).replaceQuery("first={first}&max={max}")
                            .build(Math.max(first - max, 0), max))
                    .rel("prev").build());
        }

        return links.toArray(new Link[links.size()]);
    }
}
