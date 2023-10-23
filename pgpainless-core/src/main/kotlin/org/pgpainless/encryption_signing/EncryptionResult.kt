// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.util.*
import org.bouncycastle.extensions.matches
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.util.MultiMap

data class EncryptionResult(
    val encryptionAlgorithm: SymmetricKeyAlgorithm,
    val compressionAlgorithm: CompressionAlgorithm,
    val detachedSignatures: MultiMap<SubkeyIdentifier, PGPSignature>,
    val recipients: Set<SubkeyIdentifier>,
    val fileName: String,
    val modificationDate: Date,
    val fileEncoding: StreamEncoding
) {

    /**
     * Return true, if the message is marked as for-your-eyes-only. This is typically done by
     * setting the filename "_CONSOLE".
     *
     * @return is message for your eyes only?
     */
    val isForYourEyesOnly: Boolean
        get() = PGPLiteralData.CONSOLE == fileName

    /**
     * Returns true, if the message was encrypted for at least one subkey of the given certificate.
     *
     * @param certificate certificate
     * @return true if encrypted for 1+ subkeys, false otherwise.
     */
    fun isEncryptedFor(certificate: PGPPublicKeyRing) = recipients.any { certificate.matches(it) }

    companion object {
        /**
         * Create a builder for the encryption result class.
         *
         * @return builder
         */
        @JvmStatic fun builder() = Builder()
    }

    class Builder {
        var _encryptionAlgorithm: SymmetricKeyAlgorithm? = null
        var _compressionAlgorithm: CompressionAlgorithm? = null

        val detachedSignatures: MultiMap<SubkeyIdentifier, PGPSignature> = MultiMap()
        val recipients: Set<SubkeyIdentifier> = mutableSetOf()
        private var _fileName = ""
        private var _modificationDate = Date(0)
        private var _encoding = StreamEncoding.BINARY

        fun setEncryptionAlgorithm(encryptionAlgorithm: SymmetricKeyAlgorithm) = apply {
            _encryptionAlgorithm = encryptionAlgorithm
        }

        fun setCompressionAlgorithm(compressionAlgorithm: CompressionAlgorithm) = apply {
            _compressionAlgorithm = compressionAlgorithm
        }

        fun setFileName(fileName: String) = apply { _fileName = fileName }

        fun setModificationDate(modificationDate: Date) = apply {
            _modificationDate = modificationDate
        }

        fun setFileEncoding(encoding: StreamEncoding) = apply { _encoding = encoding }

        fun addRecipient(recipient: SubkeyIdentifier) = apply {
            (recipients as MutableSet).add(recipient)
        }

        fun addDetachedSignature(
            signingSubkeyIdentifier: SubkeyIdentifier,
            detachedSignature: PGPSignature
        ) = apply { detachedSignatures.put(signingSubkeyIdentifier, detachedSignature) }

        fun build(): EncryptionResult {
            checkNotNull(_encryptionAlgorithm) { "Encryption algorithm not set." }
            checkNotNull(_compressionAlgorithm) { "Compression algorithm not set." }

            return EncryptionResult(
                _encryptionAlgorithm!!,
                _compressionAlgorithm!!,
                detachedSignatures,
                recipients,
                _fileName,
                _modificationDate,
                _encoding)
        }
    }
}
