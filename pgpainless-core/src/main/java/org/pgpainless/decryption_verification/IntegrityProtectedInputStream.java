// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.pgpainless.exception.ModificationDetectionException;

public class IntegrityProtectedInputStream extends InputStream {

    private final InputStream inputStream;
    private final PGPEncryptedData encryptedData;
    private final ConsumerOptions options;

    public IntegrityProtectedInputStream(InputStream inputStream, PGPEncryptedData encryptedData, ConsumerOptions options) {
        this.inputStream = inputStream;
        this.encryptedData = encryptedData;
        this.options = options;
    }

    @Override
    public int read() throws IOException {
        return inputStream.read();
    }

    @Override
    public int read(@Nonnull byte[] b, int offset, int length) throws IOException {
        return inputStream.read(b, offset, length);
    }

    @Override
    public void close() throws IOException {
        if (encryptedData.isIntegrityProtected() && !options.isIgnoreMDCErrors()) {
            try {
                if (!encryptedData.verify()) {
                    throw new ModificationDetectionException();
                }
            } catch (PGPException e) {
                throw new IOException("Failed to verify integrity protection", e);
            }
        }
    }
}
