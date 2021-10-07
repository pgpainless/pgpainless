// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop;

public class ByteArrayAndResult<T> {

    private final byte[] bytes;
    private final T result;

    public ByteArrayAndResult(byte[] bytes, T result) {
        this.bytes = bytes;
        this.result = result;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public T getResult() {
        return result;
    }
}
