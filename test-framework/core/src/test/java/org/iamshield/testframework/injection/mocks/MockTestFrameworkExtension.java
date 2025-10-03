package org.iamshield.testframework.injection.mocks;

import org.iamshield.testframework.TestFrameworkExtension;
import org.iamshield.testframework.injection.Supplier;

import java.util.List;

public class MockTestFrameworkExtension implements TestFrameworkExtension {

    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(
                new MockParentSupplier(),
                new MockParent2Supplier(),
                new MockChildSupplier()
        );
    }

}
