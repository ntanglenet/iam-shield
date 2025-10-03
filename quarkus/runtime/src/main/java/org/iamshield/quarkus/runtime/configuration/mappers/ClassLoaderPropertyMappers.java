package org.iamshield.quarkus.runtime.configuration.mappers;

import io.smallrye.config.ConfigSourceInterceptorContext;
import org.iamshield.config.ClassLoaderOptions;
import org.iamshield.quarkus.runtime.Environment;
import org.iamshield.quarkus.runtime.configuration.IgnoredArtifacts;

import static org.iamshield.config.ClassLoaderOptions.QUARKUS_REMOVED_ARTIFACTS_PROPERTY;
import static org.iamshield.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

import java.util.List;

final class ClassLoaderPropertyMappers implements PropertyMapperGrouping {

    @Override
    public List<PropertyMapper<?>> getPropertyMappers() {
        return List.of(
                fromOption(ClassLoaderOptions.IGNORE_ARTIFACTS)
                        .to(QUARKUS_REMOVED_ARTIFACTS_PROPERTY)
                        .transformer(ClassLoaderPropertyMappers::resolveIgnoredArtifacts)
                        .build()
        );
    }

    private static String resolveIgnoredArtifacts(String value, ConfigSourceInterceptorContext context) {
        if (Environment.isRebuildCheck() || Environment.isRebuild()) {
            return String.join(",", IgnoredArtifacts.getDefaultIgnoredArtifacts());
        }

        return value;
    }
}
