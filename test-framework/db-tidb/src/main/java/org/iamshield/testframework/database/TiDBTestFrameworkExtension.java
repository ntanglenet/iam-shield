package org.iamshield.testframework.database;

import org.iamshield.testframework.TestFrameworkExtension;
import org.iamshield.testframework.injection.Supplier;

import java.util.List;

public class TiDBTestFrameworkExtension implements TestFrameworkExtension {

    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(new TiDBDatabaseSupplier());
    }
}
