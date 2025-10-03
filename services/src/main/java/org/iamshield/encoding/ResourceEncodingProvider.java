package org.iamshield.encoding;

import org.iamshield.provider.Provider;

import java.io.IOException;
import java.io.InputStream;

public interface ResourceEncodingProvider extends Provider {

    InputStream getEncodedStream(StreamSupplier producer, String... path);

    String getEncoding();

    @Override
    default void close() {
    }

    interface StreamSupplier {

        InputStream getInputStream() throws IOException;

    }

}
