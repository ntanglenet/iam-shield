package org.iamshield.testframework.realm;

import jakarta.ws.rs.NotFoundException;
import java.util.List;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.iamshield.admin.client.resource.ClientResource;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.testframework.annotations.InjectClient;
import org.iamshield.testframework.injection.InstanceContext;
import org.iamshield.testframework.injection.RequestedInstance;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.injection.SupplierHelpers;
import org.iamshield.testframework.util.ApiUtil;

public class ClientSupplier implements Supplier<ManagedClient, InjectClient> {

    @Override
    public ManagedClient getValue(InstanceContext<ManagedClient, InjectClient> instanceContext) {
        ManagedRealm realm = instanceContext.getDependency(ManagedRealm.class, instanceContext.getAnnotation().realmRef());

        String attachTo = instanceContext.getAnnotation().attachTo();
        boolean managed = attachTo.isEmpty();

        ClientRepresentation clientRepresentation;

        if (managed) {
            ClientConfig config = SupplierHelpers.getInstance(instanceContext.getAnnotation().config());
            clientRepresentation = config.configure(ClientConfigBuilder.create()).build();

            if (clientRepresentation.getClientId() == null) {
                clientRepresentation.setClientId(SupplierHelpers.createName(instanceContext));
            }

            Response response = realm.admin().clients().create(clientRepresentation);
            if (Status.CONFLICT.equals(Status.fromStatusCode(response.getStatus()))) {
                throw new IllegalStateException("Client already exist with client id: " + clientRepresentation.getClientId());
            }
            clientRepresentation.setId(ApiUtil.handleCreatedResponse(response));
        } else {
            List<ClientRepresentation> clients = realm.admin().clients().findByClientId(attachTo);
            if (clients.isEmpty()) {
                throw new IllegalStateException("No client found with client id: " + attachTo);
            }
            clientRepresentation = clients.get(0);
        }

        instanceContext.addNote("managed", managed);

        ClientResource clientResource = realm.admin().clients().get(clientRepresentation.getId());
        return new ManagedClient(clientRepresentation, clientResource);
    }

    @Override
    public boolean compatible(InstanceContext<ManagedClient, InjectClient> a, RequestedInstance<ManagedClient, InjectClient> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public void close(InstanceContext<ManagedClient, InjectClient> instanceContext) {
        if (instanceContext.getNote("managed", Boolean.class)) {
            try {
                instanceContext.getValue().admin().remove();
            } catch (NotFoundException ex) {}
        }
    }

}
