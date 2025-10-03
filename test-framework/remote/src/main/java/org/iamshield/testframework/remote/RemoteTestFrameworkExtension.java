package org.iamshield.testframework.remote;

import org.iamshield.testframework.TestFrameworkExtension;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.remote.timeoffset.TimeOffsetSupplier;
import org.iamshield.testframework.remote.runonserver.RunOnServerSupplier;
import org.iamshield.testframework.remote.runonserver.TestClassServerSupplier;

import java.util.List;

public class RemoteTestFrameworkExtension implements TestFrameworkExtension {
    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(
                new TimeOffsetSupplier(),
                new RunOnServerSupplier(),
                new RemoteProvidersSupplier(),
                new TestClassServerSupplier()
        );
    }

    @Override
    public List<Class<?>> alwaysEnabledValueTypes() {
        return List.of(RemoteProviders.class);
    }
}
