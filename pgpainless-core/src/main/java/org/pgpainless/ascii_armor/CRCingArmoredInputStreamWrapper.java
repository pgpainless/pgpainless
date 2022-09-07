// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.ascii_armor;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;

import javax.annotation.Nonnull;

/**
 * Utility class that causes read(bytes, offset, length) to properly throw exceptions
 * caused by faulty CRC checksums.
 *
 * Furthermore, this class swallows exceptions from BC's ArmoredInputStream that are caused
 * by missing CRC checksums.
 */
public class CRCingArmoredInputStreamWrapper extends ArmoredInputStream {

    private final ArmoredInputStream inputStream;

    public CRCingArmoredInputStreamWrapper(ArmoredInputStream inputStream) throws IOException {
        super(inputStream, false);
        this.inputStream = inputStream;
    }

    @Override
    public boolean isClearText() {
        return inputStream.isClearText();
    }

    @Override
    public boolean isEndOfStream() {
        return inputStream.isEndOfStream();
    }

    @Override
    public String getArmorHeaderLine() {
        return inputStream.getArmorHeaderLine();
    }

    @Override
    public String[] getArmorHeaders() {
        return inputStream.getArmorHeaders();
    }

    @Override
    public int read() throws IOException {
        try {
            return inputStream.read();
        } catch (IOException e) {
            if (e.getMessage().equals("no crc found in armored message.") || e.getMessage().equals("crc check not found.")) {
                // swallow exception
                return -1;
            } else {
                throw e;
            }
        }
    }

    @Override
    public int read(@Nonnull byte[] b) throws IOException {
        return read(b, 0, b.length);
    }
    /**
     * Reads up to <code>len</code> bytes of data from the input stream into
     * an array of bytes.  An attempt is made to read as many as
     * <code>len</code> bytes, but a smaller number may be read.
     * The number of bytes actually read is returned as an integer.
     *
     * The first byte read is stored into element <code>b[off]</code>, the
     * next one into <code>b[off+1]</code>, and so on. The number of bytes read
     * is, at most, equal to <code>len</code>.
     *
     * NOTE: We need to override the custom behavior of Java's {@link InputStream#read(byte[], int, int)},
     * as the upstream method silently swallows {@link IOException IOExceptions}.
     * This would cause CRC checksum errors to go unnoticed.
     *
     * @see <a href="https://github.com/bcgit/bc-java/issues/998">Related BC bug report</a>
     * @param b byte array
     * @param off offset at which we start writing data to the array
     * @param len number of bytes we write into the array
     * @return total number of bytes read into the buffer
     *
     * @throws IOException if an exception happens AT ANY POINT
     */
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        checkIndexSize(b.length, off, len);

        if (len == 0) {
            return 0;
        }

        int c = read();
        if (c == -1) {
            return -1;
        }
        b[off] = (byte) c;

        int i = 1;
        for (; i < len ; i++) {
            c = read();
            if (c == -1) {
                break;
            }
            b[off + i] = (byte) c;
        }
        return i;
    }

    private void checkIndexSize(int size, int off, int len) {
        if (off < 0 || len < 0) {
            throw new IndexOutOfBoundsException("Offset and length cannot be negative.");
        }
        if (size < off + len) {
            throw new IndexOutOfBoundsException("Invalid offset and length.");
        }
    }

    @Override
    public long skip(long n) throws IOException {
        return inputStream.skip(n);
    }

    @Override
    public int available() throws IOException {
        return inputStream.available();
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
    }

    @Override
    public synchronized void mark(int readlimit) {
        inputStream.mark(readlimit);
    }

    @Override
    public synchronized void reset() throws IOException {
        inputStream.reset();
    }

    @Override
    public boolean markSupported() {
        return inputStream.markSupported();
    }
}
