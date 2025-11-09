package org.iamshield.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.binder.cache.CaffeineStatsCounter;
import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;

import java.util.concurrent.TimeUnit;

public class DefaultAlternativeLookupProviderFactory implements AlternativeLookupProviderFactory {

    private Cache<String, String> lookupCache;

    @Override
    public String getId() {
        return "default";
    }

    @Override
    public AlternativeLookupProvider create(IAMShieldSession session) {
        return new DefaultAlternativeLookupProvider(lookupCache);
    }

    @Override
    public void init(Config.Scope config) {
        Integer maximumSize = config.getInt("maximumSize", 1000);
        Integer expireAfter = config.getInt("expireAfter", 60);

        CaffeineStatsCounter metrics = new CaffeineStatsCounter(Metrics.globalRegistry, "lookup");

        this.lookupCache = Caffeine.newBuilder()
                .maximumSize(maximumSize)
                .expireAfterAccess(expireAfter, TimeUnit.MINUTES)
                .recordStats(() -> metrics)
                .build();

        metrics.registerSizeMetric(lookupCache);
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
        lookupCache.cleanUp();
        lookupCache = null;
    }

}
