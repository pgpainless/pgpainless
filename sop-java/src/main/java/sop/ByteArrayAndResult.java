// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * Tuple of a byte array and associated result object.
 * @param <T> type of result
 */
public class ByteArrayAndResult<T> {

    private final byte[] bytes;
    private final T result;

    public ByteArrayAndResult(byte[] bytes, T result) {
        this.bytes = bytes;
        this.result = result;
    }

    /**
     * Return the byte array part.
     *
     * @return bytes
     */
    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Return the result part.
     *
     * @return result
     */
    public T getResult() {
        return result;
    }

    /**
     * Return the byte array part as an {@link InputStream}.
     *
     * @return input stream
     */
    public InputStream getInputStream() {
        return new ByteArrayInputStream(getBytes());
    }
}
