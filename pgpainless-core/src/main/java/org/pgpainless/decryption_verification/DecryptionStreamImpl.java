// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.util.io.Streams;

/**
 * Decryption Stream that handles updating and verification of detached signatures,
 * as well as verification of integrity-protected input streams once the stream gets closed.
 */
public class DecryptionStreamImpl extends DecryptionStream {

    private final InputStream inputStream;
    private final IntegrityProtectedInputStream integrityProtectedInputStream;
    private final InputStream armorStream;

    /**
     * Create an input stream that handles decryption and - if necessary - integrity protection verification.
     *
     * @param wrapped underlying input stream
     * @param resultBuilder builder for decryption metadata like algorithms, recipients etc.
     * @param integrityProtectedInputStream in case of data encrypted using SEIP packet close this stream to check integrity
     * @param armorStream armor stream to verify CRC checksums
     */
    DecryptionStreamImpl(@Nonnull InputStream wrapped,
                         @Nonnull OpenPgpMetadata.Builder resultBuilder,
                         IntegrityProtectedInputStream integrityProtectedInputStream,
                         InputStream armorStream) {
        super(resultBuilder);
        this.inputStream = wrapped;
        this.integrityProtectedInputStream = integrityProtectedInputStream;
        this.armorStream = armorStream;
    }

    @Override
    public void close() throws IOException {
        if (armorStream != null) {
            Streams.drain(armorStream);
        }
        inputStream.close();
        if (integrityProtectedInputStream != null) {
            integrityProtectedInputStream.close();
        }
        super.close();
    }

    @Override
    public int read() throws IOException {
        int r = inputStream.read();
        return r;
    }

    @Override
    public int read(@Nonnull byte[] bytes, int offset, int length) throws IOException {
        int read = inputStream.read(bytes, offset, length);
        return read;
    }

}
