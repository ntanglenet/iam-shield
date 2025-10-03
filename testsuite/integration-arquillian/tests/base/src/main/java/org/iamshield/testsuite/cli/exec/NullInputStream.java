package org.iamshield.testsuite.cli.exec;

import java.io.IOException;
import java.io.InputStream;

class NullInputStream extends InputStream {

    @Override
    public int read() throws IOException {
        return -1;
    }
}