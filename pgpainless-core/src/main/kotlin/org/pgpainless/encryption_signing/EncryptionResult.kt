// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.util.*
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.matches
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.util.MultiMap

data class EncryptionResult(
    val encryptionMechanism: MessageEncryptionMechanism,
    val compressionAlgorithm: CompressionAlgorithm,
    val detachedDocumentSignatures: OpenPGPSignatureSet<OpenPGPDocumentSignature>,
    val recipients: Set<SubkeyIdentifier>,
    val fileName: String,
    val modificationDate: Date,
    val fileEncoding: StreamEncoding
) {

    @Deprecated(
        "Use encryptionMechanism instead.", replaceWith = ReplaceWith("encryptionMechanism"))
    val encryptionAlgorithm: SymmetricKeyAlgorithm?
        get() = SymmetricKeyAlgorithm.fromId(encryptionMechanism.symmetricKeyAlgorithm)

    @Deprecated(
        "Use detachedSignatures instead", replaceWith = ReplaceWith("detachedDocumentSignatures"))
    // TODO: Remove in 2.1
    val detachedSignatures: MultiMap<SubkeyIdentifier, PGPSignature>
        get() {
            val map = MultiMap<SubkeyIdentifier, PGPSignature>()
            detachedDocumentSignatures.signatures
                .map { SubkeyIdentifier(it.issuer) to it.signature }
                .forEach { map.put(it.first, it.second) }
            return map
        }

    /**
     * Return true, if the message is marked as for-your-eyes-only. This is typically done by
     * setting the filename "_CONSOLE".
     *
     * @return is message for your eyes only?
     */
    val isForYourEyesOnly: Boolean
        get() = PGPLiteralData.CONSOLE == fileName

    fun isEncryptedFor(certificate: OpenPGPCertificate) =
        recipients.any { certificate.getKey(it.keyIdentifier) != null }

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
        var _encryptionMechanism: MessageEncryptionMechanism =
            MessageEncryptionMechanism.unencrypted()
        var _compressionAlgorithm: CompressionAlgorithm? = null

        val detachedSignatures: MutableList<OpenPGPDocumentSignature> = mutableListOf()
        val recipients: Set<SubkeyIdentifier> = mutableSetOf()
        private var _fileName = ""
        private var _modificationDate = Date(0)
        private var _encoding = StreamEncoding.BINARY

        fun setEncryptionMechanism(mechanism: MessageEncryptionMechanism): Builder = apply {
            _encryptionMechanism = mechanism
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

        fun addDetachedSignature(signature: OpenPGPDocumentSignature): Builder = apply {
            detachedSignatures.add(signature)
        }

        fun build(): EncryptionResult {
            checkNotNull(_compressionAlgorithm) { "Compression algorithm not set." }

            return EncryptionResult(
                _encryptionMechanism,
                _compressionAlgorithm!!,
                OpenPGPSignatureSet(detachedSignatures),
                recipients,
                _fileName,
                _modificationDate,
                _encoding)
        }
    }
}
