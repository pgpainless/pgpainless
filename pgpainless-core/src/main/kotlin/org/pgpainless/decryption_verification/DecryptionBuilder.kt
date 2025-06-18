// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.InputStream
import org.pgpainless.PGPainless

/**
 * Builder class that takes an [InputStream] of ciphertext (or plaintext signed data) and combines
 * it with a configured [ConsumerOptions] object to form a [DecryptionStream] which can be used to
 * decrypt an OpenPGP message or verify signatures.
 */
class DecryptionBuilder(private val api: PGPainless) : DecryptionBuilderInterface {

    override fun onInputStream(inputStream: InputStream): DecryptionBuilderInterface.DecryptWith {
        return DecryptWithImpl(inputStream, api)
    }

    class DecryptWithImpl(val inputStream: InputStream, val api: PGPainless) :
        DecryptionBuilderInterface.DecryptWith {

        override fun withOptions(consumerOptions: ConsumerOptions): DecryptionStream {
            return OpenPgpMessageInputStream.create(inputStream, consumerOptions, api)
        }
    }
}
