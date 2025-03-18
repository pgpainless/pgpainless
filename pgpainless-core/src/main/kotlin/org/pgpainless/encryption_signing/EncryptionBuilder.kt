// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.OutputStream
import org.pgpainless.PGPainless
import org.pgpainless.util.NullOutputStream

class EncryptionBuilder(private val api: PGPainless) : EncryptionBuilderInterface {
    override fun onOutputStream(
        outputStream: OutputStream
    ): EncryptionBuilderInterface.WithOptions {
        return WithOptionsImpl(outputStream, api)
    }

    override fun discardOutput(): EncryptionBuilderInterface.WithOptions {
        return onOutputStream(NullOutputStream())
    }

    class WithOptionsImpl(val outputStream: OutputStream, private val api: PGPainless) :
        EncryptionBuilderInterface.WithOptions {

        override fun withOptions(options: ProducerOptions): EncryptionStream {
            return EncryptionStream(outputStream, options, api)
        }
    }
}
