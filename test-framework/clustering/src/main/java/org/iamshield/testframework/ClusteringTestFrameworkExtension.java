package org.iamshield.testframework;

import org.iamshield.testframework.clustering.LoadBalancerSupplier;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.server.ClusteredIAMShieldServerSupplier;

import java.util.List;

public class ClusteringTestFrameworkExtension implements TestFrameworkExtension {

    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(new ClusteredIAMShieldServerSupplier(), new LoadBalancerSupplier());
    }
}
