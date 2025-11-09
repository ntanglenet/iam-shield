package org.iamshield.quarkus.runtime.configuration.mappers;

import org.iamshield.config.MetricsOptions;

import static org.iamshield.quarkus.runtime.configuration.Configuration.isTrue;
import static org.iamshield.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

import java.util.List;


final class MetricsPropertyMappers implements PropertyMapperGrouping {

    public static final String METRICS_ENABLED_MSG = "metrics are enabled";

    @Override
    public List<PropertyMapper<?>> getPropertyMappers() {
        return List.of(
                fromOption(MetricsOptions.METRICS_ENABLED)
                        .to("quarkus.micrometer.enabled")
                        .build()
        );
    }

    public static boolean metricsEnabled() {
        return isTrue(MetricsOptions.METRICS_ENABLED);
    }
}
