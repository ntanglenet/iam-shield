package org.iamshield.protocol.docker.mapper;


import org.junit.Test;
import org.iamshield.models.AuthenticatedClientSessionModel;
import org.iamshield.models.ProtocolMapperModel;
import org.iamshield.protocol.TestAuthenticatedClientSessionModel;
import org.iamshield.protocol.docker.DockerAuthV2Protocol;
import org.iamshield.representations.docker.DockerAccess;
import org.iamshield.representations.docker.DockerResponseToken;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;

public class AllowAllDockerProtocolMapperTest {

    @Test
    public void transformsResourceScope() {
        DockerResponseToken dockerResponseToken = new DockerResponseToken();
        AuthenticatedClientSessionModel authenticatedClientSessionModel = new TestAuthenticatedClientSessionModel();
        authenticatedClientSessionModel.setNote(DockerAuthV2Protocol.SCOPE_PARAM, "repository:my-image:pull,push");

        DockerResponseToken result = new AllowAllDockerProtocolMapper().transformDockerResponseToken(dockerResponseToken, new ProtocolMapperModel(), null, null, authenticatedClientSessionModel);

        assertThat(result.getAccessItems(), containsInAnyOrder(new DockerAccess("repository:my-image:pull,push")));
    }

    @Test
    public void transformsResourceScopeNull() {
        DockerResponseToken dockerResponseToken = new DockerResponseToken();
        AuthenticatedClientSessionModel authenticatedClientSessionModel = new TestAuthenticatedClientSessionModel();
        authenticatedClientSessionModel.setNote(DockerAuthV2Protocol.SCOPE_PARAM, null);

        DockerResponseToken result = new AllowAllDockerProtocolMapper().transformDockerResponseToken(dockerResponseToken, new ProtocolMapperModel(), null, null, authenticatedClientSessionModel);

        assertThat(result.getAccessItems(), containsInAnyOrder());
    }

    @Test
    public void transformsMultipleResourceScopes() {
        DockerResponseToken dockerResponseToken = new DockerResponseToken();
        AuthenticatedClientSessionModel authenticatedClientSessionModel = new TestAuthenticatedClientSessionModel();
        authenticatedClientSessionModel.setNote(DockerAuthV2Protocol.SCOPE_PARAM, "repository:my-image:pull,push repository:my-base-image:pull");

        DockerResponseToken result = new AllowAllDockerProtocolMapper().transformDockerResponseToken(dockerResponseToken, new ProtocolMapperModel(), null, null, authenticatedClientSessionModel);

        assertThat(result.getAccessItems(), containsInAnyOrder(new DockerAccess("repository:my-image:pull,push"), new DockerAccess("repository:my-base-image:pull")));
    }

}