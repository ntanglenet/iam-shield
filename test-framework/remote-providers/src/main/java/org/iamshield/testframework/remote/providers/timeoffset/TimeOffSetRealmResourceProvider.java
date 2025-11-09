package org.iamshield.testframework.remote.providers.timeoffset;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.iamshield.common.util.Time;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.services.resource.RealmResourceProvider;

import java.util.Map;

public class TimeOffSetRealmResourceProvider implements RealmResourceProvider {

    private final IAMShieldSession session;
    private final String KEY_OFFSET = "offset";

    public TimeOffSetRealmResourceProvider(IAMShieldSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    @GET
    @Path("/")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTimeOffset() {
        int offset = Time.getOffset();
        var time = Map.of(KEY_OFFSET, offset);
        return Response.ok(time).build();
    }

    @PUT
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setTimeOffset(Map<String, Integer> time) {
        if (!time.containsKey(KEY_OFFSET)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        Time.setOffset(time.get(KEY_OFFSET));
        return Response.ok().header("Content-Type", MediaType.APPLICATION_JSON).build();
    }
}
