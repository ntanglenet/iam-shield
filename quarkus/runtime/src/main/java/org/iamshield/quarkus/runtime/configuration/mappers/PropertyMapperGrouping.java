package org.iamshield.quarkus.runtime.configuration.mappers;

import java.util.List;

import org.iamshield.quarkus.runtime.cli.Picocli;

public interface PropertyMapperGrouping {

    List<? extends PropertyMapper<?>> getPropertyMappers();

    default void validateConfig(Picocli picocli) {

    }

}
