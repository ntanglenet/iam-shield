package org.iamshield.infinispan.module.configuration.global;

import org.infinispan.commons.configuration.Builder;
import org.infinispan.commons.configuration.Combine;
import org.infinispan.commons.configuration.attributes.AttributeSet;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.iamshield.models.IAMShieldSessionFactory;

public class IAMShieldConfigurationBuilder implements Builder<IAMShieldConfiguration> {

    private final AttributeSet attributes;

    public IAMShieldConfigurationBuilder(GlobalConfigurationBuilder unused) {
        attributes = IAMShieldConfiguration.attributeSet();
    }

    @Override
    public IAMShieldConfiguration create() {
        return new IAMShieldConfiguration(attributes.protect());
    }

    @Override
    public Builder<?> read(IAMShieldConfiguration template, Combine combine) {
        attributes.read(template.attributes(), combine);
        return this;
    }

    @Override
    public AttributeSet attributes() {
        return attributes;
    }

    @Override
    public void validate() {

    }

    public IAMShieldConfigurationBuilder setIAMShieldSessionFactory(IAMShieldSessionFactory keycloakSessionFactory) {
        attributes.attribute(IAMShieldConfiguration.KEYCLOAK_SESSION_FACTORY).set(keycloakSessionFactory);
        return this;
    }

}
