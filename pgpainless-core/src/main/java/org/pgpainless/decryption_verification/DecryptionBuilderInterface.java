// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;

public interface DecryptionBuilderInterface {

    /**
     * Create a {@link DecryptionStreamImpl} on an {@link InputStream} which contains the encrypted and/or signed data.
     *
     * @param inputStream encrypted and/or signed data.
     * @return api handle
     */
    DecryptWith onInputStream(@Nonnull InputStream inputStream);

    interface DecryptWith {

        /**
         * Add options for decryption / signature verification, such as keys, passphrases etc.
         *
         * @param consumerOptions consumer options
         * @return decryption stream
         * @throws PGPException in case of an OpenPGP related error
         * @throws IOException in case of an IO error
         */
        DecryptionStream withOptions(ConsumerOptions consumerOptions) throws PGPException, IOException;

    }
}
