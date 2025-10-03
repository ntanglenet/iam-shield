package org.iamshield.protocol.saml.mappers;

import org.iamshield.dom.saml.v2.metadata.EntityDescriptorType;
import org.iamshield.models.IdentityProviderMapperModel;

public interface SamlMetadataDescriptorUpdater
{
    void updateMetadata(IdentityProviderMapperModel mapperModel, EntityDescriptorType descriptor);
}