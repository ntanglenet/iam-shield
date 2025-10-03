package org.iamshield.quarkus.runtime.configuration.mappers;

import static org.iamshield.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

import java.util.List;

import org.iamshield.common.Profile;
import org.iamshield.common.Profile.Feature;
import org.iamshield.common.crypto.FipsMode;
import org.iamshield.config.SecurityOptions;

import io.smallrye.config.ConfigSourceInterceptorContext;

final class SecurityPropertyMappers implements PropertyMapperGrouping {


    @Override
    public List<PropertyMapper<?>> getPropertyMappers() {
        return List.of(
                fromOption(SecurityOptions.FIPS_MODE).transformer(SecurityPropertyMappers::resolveFipsMode)
                        .paramLabel("mode")
                        .build()
        );
    }

    private static String resolveFipsMode(String value, ConfigSourceInterceptorContext context) {
        if (value == null) {
            if (Profile.isFeatureEnabled(Feature.FIPS)) {
                return FipsMode.NON_STRICT.toString();
            }

            return FipsMode.DISABLED.toString();
        }

        return value;
    }
}
