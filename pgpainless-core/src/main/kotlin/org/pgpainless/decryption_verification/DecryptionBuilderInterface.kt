// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.IOException
import java.io.InputStream
import org.bouncycastle.openpgp.PGPException

interface DecryptionBuilderInterface {

    /**
     * Create a [DecryptionStream] on an [InputStream] which contains the encrypted and/or signed
     * data.
     *
     * @param inputStream encrypted and/or signed data.
     * @return api handle
     */
    fun onInputStream(inputStream: InputStream): DecryptWith

    interface DecryptWith {

        /**
         * Add options for decryption / signature verification, such as keys, passphrases etc.
         *
         * @param consumerOptions consumer options
         * @return decryption stream
         * @throws PGPException in case of an OpenPGP related error
         * @throws IOException in case of an IO error
         */
        @Throws(PGPException::class, IOException::class)
        fun withOptions(consumerOptions: ConsumerOptions): DecryptionStream
    }
}
