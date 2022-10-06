package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class DelayedTeeInputStreamInputStream extends InputStream {

    private int last = -1;
    private final InputStream inputStream;
    private final OutputStream outputStream;

    public DelayedTeeInputStreamInputStream(InputStream inputStream, OutputStream outputStream) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
    }

    @Override
    public int read() throws IOException {
        if (last != -1) {
            outputStream.write(last);
        }
        last = inputStream.read();
        return last;
    }

    /**
     * Squeeze the last byte out and update the output stream.
     *
     * @throws IOException in case of an IO error
     */
    public void squeeze() throws IOException {
        if (last != -1) {
            outputStream.write(last);
        }
        last = -1;
    }
}
