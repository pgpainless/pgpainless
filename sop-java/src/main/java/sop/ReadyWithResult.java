// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import sop.exception.SOPGPException;

public abstract class ReadyWithResult<T> {

    /**
     * Write the data eg. decrypted plaintext to the provided output stream and return the result of the
     * processing operation.
     *
     * @param outputStream output stream
     * @return result, eg. signatures
     *
     * @throws IOException in case of an IO error
     * @throws SOPGPException.NoSignature
     */
    public abstract T writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature;

    public ByteArrayAndResult<T> toBytes() throws IOException, SOPGPException.NoSignature {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        T result = writeTo(bytes);
        return new ByteArrayAndResult<>(bytes.toByteArray(), result);
    }
}
