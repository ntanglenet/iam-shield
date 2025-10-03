package org.iamshield.protocol.docker.mapper;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.protocol.ProtocolMapper;
import org.iamshield.protocol.docker.DockerAuthV2Protocol;
import org.iamshield.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public abstract class DockerAuthV2ProtocolMapper implements ProtocolMapper {

    public static final String DOCKER_AUTH_V2_CATEGORY = "Docker Auth Mapper";

    @Override
    public String getProtocol() {
        return DockerAuthV2Protocol.LOGIN_PROTOCOL;
    }

    @Override
    public String getDisplayCategory() {
        return DOCKER_AUTH_V2_CATEGORY;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public final ProtocolMapper create(final IAMShieldSession session) {
        throw new UnsupportedOperationException("The create method is not supported by this mapper");
    }

    @Override
    public void init(final Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(final IAMShieldSessionFactory factory) {
        // no-op
    }
}
