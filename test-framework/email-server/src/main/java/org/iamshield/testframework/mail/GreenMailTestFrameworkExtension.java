package org.iamshield.testframework.mail;

import org.iamshield.testframework.TestFrameworkExtension;
import org.iamshield.testframework.injection.Supplier;

import java.util.List;

public class GreenMailTestFrameworkExtension implements TestFrameworkExtension {

    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(new GreenMailSupplier());
    }

}
