// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class Ready {

    /**
     * Write the data to the provided output stream.
     *
     * @param outputStream output stream
     * @throws IOException in case of an IO error
     */
    public abstract void writeTo(OutputStream outputStream) throws IOException;

    /**
     * Return the data as a byte array by writing it to a {@link ByteArrayOutputStream} first and then returning
     * the array.
     *
     * @return data as byte array
     * @throws IOException in case of an IO error
     */
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        writeTo(bytes);
        return bytes.toByteArray();
    }
}
