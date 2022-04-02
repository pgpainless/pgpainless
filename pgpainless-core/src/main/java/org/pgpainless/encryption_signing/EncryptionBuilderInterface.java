// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import java.io.IOException;
import java.io.OutputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;

public interface EncryptionBuilderInterface {

    /**
     * Create a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data that
     * shall be encrypted and or signed.
     *
     * @param outputStream output stream of the plain data.
     * @return api handle
     */
    WithOptions onOutputStream(@Nonnull OutputStream outputStream);

    interface WithOptions {

        /**
         * Create an {@link EncryptionStream} with the given options (recipients, signers, algorithms...).
         *
         * @param options options
         * @return encryption stream
         *
         * @throws PGPException if something goes wrong during encryption stream preparation
         * @throws IOException if something goes wrong during encryption stream preparation (writing headers)
         */
        EncryptionStream withOptions(ProducerOptions options) throws PGPException, IOException;

    }
}
