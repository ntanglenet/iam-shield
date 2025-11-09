package org.iamshield.infinispan.module.configuration.global;

import org.infinispan.commons.configuration.BuiltBy;
import org.infinispan.commons.configuration.attributes.AttributeDefinition;
import org.infinispan.commons.configuration.attributes.AttributeSet;
import org.iamshield.models.IAMShieldSessionFactory;

@BuiltBy(IAMShieldConfigurationBuilder.class)
public class IAMShieldConfiguration {

    static final AttributeDefinition<IAMShieldSessionFactory> KEYCLOAK_SESSION_FACTORY = AttributeDefinition.builder("keycloak-session-factory", null, IAMShieldSessionFactory.class)
            .global(true)
            .autoPersist(false)
            .immutable()
            .build();

    private final AttributeSet attributes;

    static AttributeSet attributeSet() {
        return new AttributeSet(IAMShieldConfiguration.class, KEYCLOAK_SESSION_FACTORY);
    }

    IAMShieldConfiguration(AttributeSet attributes) {
        this.attributes = attributes;
    }

    AttributeSet attributes() {
        return attributes;
    }

    public IAMShieldSessionFactory keycloakSessionFactory() {
        return attributes.attribute(KEYCLOAK_SESSION_FACTORY).get();
    }

}
