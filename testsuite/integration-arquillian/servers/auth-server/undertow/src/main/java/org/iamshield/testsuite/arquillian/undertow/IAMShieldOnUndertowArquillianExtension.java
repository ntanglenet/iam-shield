package org.iamshield.testsuite.arquillian.undertow;

import org.jboss.arquillian.container.spi.client.container.DeployableContainer;
import org.jboss.arquillian.core.spi.LoadableExtension;
import org.iamshield.testsuite.arquillian.undertow.lb.SimpleUndertowLoadBalancerContainer;

/**
 *
 * @author tkyjovsk
 */
public class IAMShieldOnUndertowArquillianExtension implements LoadableExtension {

    @Override
    public void register(ExtensionBuilder builder) {
        builder.service(DeployableContainer.class, IAMShieldOnUndertow.class);
        builder.service(DeployableContainer.class, SimpleUndertowLoadBalancerContainer.class);
    }

}
