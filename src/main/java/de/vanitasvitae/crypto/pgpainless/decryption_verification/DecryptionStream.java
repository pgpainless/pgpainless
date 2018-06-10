package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;

public class DecryptionStream extends InputStream {

    private final InputStream inputStream;
    private final PainlessResult.Builder resultBuilder;
    private boolean isClosed = false;

    DecryptionStream(InputStream wrapped, PainlessResult.Builder resultBuilder) {

        if (wrapped == null) {
            throw new NullPointerException("Wrapped InputStream MUST NOT be null!");
        }

        this.inputStream = wrapped;
        this.resultBuilder = resultBuilder;
    }

    @Override
    public int read() throws IOException {
        return inputStream.read();
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
        this.isClosed = true;
    }

    public PainlessResult getResult() {
        if (!isClosed) {
            throw new IllegalStateException("DecryptionStream MUST be closed before the result can be accessed.");
        }
        return resultBuilder.build();
    }
}
