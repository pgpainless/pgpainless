// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.OutputStream
import org.pgpainless.PGPainless.Companion.getPolicy
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.algorithm.negotiation.SymmetricKeyAlgorithmNegotiator.Companion.byPopularity
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class EncryptionBuilder : EncryptionBuilderInterface {
    override fun onOutputStream(
        outputStream: OutputStream
    ): EncryptionBuilderInterface.WithOptions {
        return WithOptionsImpl(outputStream)
    }

    class WithOptionsImpl(val outputStream: OutputStream) : EncryptionBuilderInterface.WithOptions {

        override fun withOptions(options: ProducerOptions): EncryptionStream {
            return EncryptionStream(outputStream, options)
        }
    }

    companion object {

        @JvmStatic val LOGGER: Logger = LoggerFactory.getLogger(EncryptionBuilder::class.java)

        /**
         * Negotiate the [SymmetricKeyAlgorithm] used for message encryption.
         *
         * @param encryptionOptions encryption options
         * @return negotiated symmetric key algorithm
         */
        @JvmStatic
        fun negotiateSymmetricEncryptionAlgorithm(
            encryptionOptions: EncryptionOptions
        ): SymmetricKeyAlgorithm {
            val preferences =
                encryptionOptions.keyViews.values
                    .map { it.preferredSymmetricKeyAlgorithms }
                    .toList()
            val algorithm =
                byPopularity()
                    .negotiate(
                        getPolicy().symmetricKeyEncryptionAlgorithmPolicy,
                        encryptionOptions.encryptionAlgorithmOverride,
                        preferences)
            LOGGER.debug(
                "Negotiation resulted in {} being the symmetric encryption algorithm of choice.",
                algorithm)
            return algorithm
        }

        @JvmStatic
        fun negotiateCompressionAlgorithm(producerOptions: ProducerOptions): CompressionAlgorithm {
            val compressionAlgorithmOverride = producerOptions.compressionAlgorithmOverride
            return compressionAlgorithmOverride
                ?: getPolicy().compressionAlgorithmPolicy.defaultCompressionAlgorithm()

            // TODO: Negotiation
        }
    }
}
