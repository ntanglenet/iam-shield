package org.iamshield.infinispan.module.factory;

import org.infinispan.factories.AbstractComponentFactory;
import org.infinispan.factories.AutoInstantiableFactory;
import org.infinispan.factories.annotations.DefaultFactoryFor;
import org.iamshield.jgroups.certificates.CertificateReloadManager;
import org.iamshield.infinispan.module.configuration.global.IAMShieldConfiguration;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.spi.infinispan.JGroupsCertificateProvider;

@DefaultFactoryFor(classes = CertificateReloadManager.class)
public class CertificateReloadManagerFactory extends AbstractComponentFactory implements AutoInstantiableFactory {

    @Override
    public Object construct(String componentName) {
        var kcConfig = globalConfiguration.module(IAMShieldConfiguration.class);
        if (kcConfig == null) {
            return null;
        }
        var sessionFactory = kcConfig.keycloakSessionFactory();
        if (supportsReloadAndRotation(sessionFactory)) {
            return new CertificateReloadManager(sessionFactory);
        }
        return null;
    }

    private boolean supportsReloadAndRotation(IAMShieldSessionFactory factory) {
        try (var session = factory.create()) {
            var provider = session.getProvider(JGroupsCertificateProvider.class);
            return provider != null && provider.isEnabled() && provider.supportRotateAndReload();
        }
    }
}
