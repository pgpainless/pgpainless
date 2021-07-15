/*
 * Copyright 2021 Paul Schaub.
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
package sop.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * {@link OutputStream} that buffers data being written into it, until its underlying output stream is being replaced.
 * At that point, first all the buffered data is being written to the underlying stream, followed by any successive
 * data that may get written to the {@link ProxyOutputStream}.
 *
 * This class is useful if we need to provide an {@link OutputStream} at one point in time where the final
 * target output stream is not yet known.
 */
public class ProxyOutputStream extends OutputStream {

    private final ByteArrayOutputStream buffer;
    private OutputStream swapped;

    public ProxyOutputStream() {
        this.buffer = new ByteArrayOutputStream();
    }

    public synchronized void replaceOutputStream(OutputStream underlying) throws IOException {
        if (underlying == null) {
            throw new NullPointerException("Underlying OutputStream cannot be null.");
        }
        this.swapped = underlying;

        byte[] bufferBytes = buffer.toByteArray();
        swapped.write(bufferBytes);
    }

    @Override
    public synchronized void write(byte[] b) throws IOException {
        if (swapped == null) {
            buffer.write(b);
        } else {
            swapped.write(b);
        }
    }

    @Override
    public synchronized void write(byte[] b, int off, int len) throws IOException {
        if (swapped == null) {
            buffer.write(b, off, len);
        } else {
            swapped.write(b, off, len);
        }
    }

    @Override
    public synchronized void flush() throws IOException {
        buffer.flush();
        if (swapped != null) {
            swapped.flush();
        }
    }

    @Override
    public synchronized void close() throws IOException {
        buffer.close();
        if (swapped != null) {
            swapped.close();
        }
    }

    @Override
    public synchronized void write(int i) throws IOException {
        if (swapped == null) {
            buffer.write(i);
        } else {
            swapped.write(i);
        }
    }
}
