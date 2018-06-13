/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
