package de.vanitasvitae.crypto.pgpainless;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface PainlessStream {

    boolean isClosed();

    class In extends InputStream implements PainlessStream {
        private final InputStream inputStream;

        private boolean isClosed = false;

        public In(InputStream inputStream) {
            this.inputStream = inputStream;
        }

        @Override
        public int read() throws IOException {
            return inputStream.read();
        }

        @Override
        public void close() throws IOException {
            inputStream.close();
            isClosed = true;
        }

        @Override
        public boolean isClosed() {
            return isClosed;
        }
    }

    class Out extends OutputStream implements PainlessStream {

        private final OutputStream outputStream;
        private boolean isClosed = false;

        public Out(OutputStream outputStream) {
            this.outputStream = outputStream;
        }

        @Override
        public boolean isClosed() {
            return isClosed;
        }

        @Override
        public void write(int i) throws IOException {
            outputStream.write(i);
        }

        @Override
        public void close() throws IOException {
            outputStream.close();
            this.isClosed = true;
        }
    }
}
