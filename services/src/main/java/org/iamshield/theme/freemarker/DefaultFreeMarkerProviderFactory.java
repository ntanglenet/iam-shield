package org.iamshield.theme.freemarker;

import freemarker.template.Template;
import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.theme.IAMShieldSanitizerMethod;

import java.util.concurrent.ConcurrentHashMap;

public class DefaultFreeMarkerProviderFactory implements FreeMarkerProviderFactory {

    private volatile DefaultFreeMarkerProvider provider;
    private ConcurrentHashMap<String, Template> cache;
    private IAMShieldSanitizerMethod kcSanitizeMethod;

    @Override
    public DefaultFreeMarkerProvider create(IAMShieldSession session) {
        if (provider == null) {
            synchronized (this) {
                if (provider == null) {
                    if (Config.scope("theme").getBoolean("cacheTemplates", true)) {
                        cache = new ConcurrentHashMap<>();
                    }
                    kcSanitizeMethod = new IAMShieldSanitizerMethod();
                    provider = new DefaultFreeMarkerProvider(cache, kcSanitizeMethod);
                }
            }
        }
        return provider;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(IAMShieldSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "default";
    }

}
