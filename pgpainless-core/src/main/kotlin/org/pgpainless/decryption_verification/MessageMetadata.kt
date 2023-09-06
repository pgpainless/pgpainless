// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPLiteralData
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.authentication.CertificateAuthority
import org.pgpainless.exception.MalformedOpenPgpMessageException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.util.SessionKey
import java.util.*
import javax.annotation.Nonnull

/**
 * View for extracting metadata about a [Message].
 */
class MessageMetadata(
        val message: Message
) {

    // ################################################################################################################
    // ###                                              Encryption                                                  ###
    // ################################################################################################################

    /**
     * The [SymmetricKeyAlgorithm] of the outermost encrypted data packet, or null if message is unencrypted.
     */
    val encryptionAlgorithm: SymmetricKeyAlgorithm?
        get() = encryptionAlgorithms.let {
            if (it.hasNext()) it.next() else null
        }

    /**
     * [Iterator] of each [SymmetricKeyAlgorithm] encountered in the message.
     * The first item returned by the iterator is the algorithm of the outermost encrypted data packet, the next item
     * that of the next nested encrypted data packet and so on.
     * The iterator might also be empty, in case of an unencrypted message.
     */
    val encryptionAlgorithms: Iterator<SymmetricKeyAlgorithm>
        get() = encryptionLayers.asSequence().map { it.algorithm }.iterator()

    val isEncrypted: Boolean
        get() = if (encryptionAlgorithm == null) false else encryptionAlgorithm != SymmetricKeyAlgorithm.NULL

    fun isEncryptedFor(keys: PGPKeyRing): Boolean {
        return encryptionLayers.asSequence().any {
            it.recipients.any { keyId ->
                keys.getPublicKey(keyId) != null
            }
        }
    }

    /**
     * [SessionKey] of the outermost encrypted data packet.
     * If the message was unencrypted, this method returns `null`.
     */
    val sessionKey: SessionKey?
        get() = sessionKeys.asSequence().firstOrNull()

    /**
     * [Iterator] of each [SessionKey] for all encrypted data packets in the message.
     * The first item returned by the iterator is the session key of the outermost encrypted data packet,
     * the next item that of the next nested encrypted data packet and so on.
     * The iterator might also be empty, in case of an unencrypted message.
     */
    val sessionKeys: Iterator<SessionKey>
        get() = encryptionLayers.asSequence().mapNotNull { it.sessionKey }.iterator()

    /**
     * [SubkeyIdentifier] of the decryption key that was used to decrypt the outermost encryption
     * layer.
     * If the message was unencrypted or was decrypted using a passphrase, this field might be `null`.
     */
    val decryptionKey: SubkeyIdentifier?
        get() = encryptionLayers.asSequence()
                .mapNotNull { it.decryptionKey }
                .firstOrNull()

    /**
     * List containing all recipient keyIDs.
     */
    val recipientKeyIds: List<Long>
        get() = encryptionLayers.asSequence()
                .map { it.recipients.toMutableList() }
                .reduce { all, keyIds -> all.addAll(keyIds); all }
                .toList()

    val encryptionLayers: Iterator<EncryptedData>
        get() = object : LayerIterator<EncryptedData>(message) {
            override fun matches(layer: Packet) = layer is EncryptedData
            override fun getProperty(last: Layer) = last as EncryptedData
        }

    // ################################################################################################################
    // ###                                             Compression                                                  ###
    // ################################################################################################################

    /**
     * [CompressionAlgorithm] of the outermost compressed data packet, or null, if the message
     * does not contain any compressed data packets.
     */
    val compressionAlgorithm: CompressionAlgorithm? = compressionAlgorithms.asSequence().firstOrNull()

    /**
     * [Iterator] of each [CompressionAlgorithm] encountered in the message.
     * The first item returned by the iterator is the algorithm of the outermost compressed data packet, the next
     * item that of the next nested compressed data packet and so on.
     * The iterator might also be empty, in case of a message without any compressed data packets.
     */
    val compressionAlgorithms: Iterator<CompressionAlgorithm>
        get() = compressionLayers.asSequence().map { it.algorithm }.iterator()

    val compressionLayers: Iterator<CompressedData>
        get() = object : LayerIterator<CompressedData>(message) {
            override fun matches(layer: Packet) = layer is CompressedData
            override fun getProperty(last: Layer) = last as CompressedData
        }

    // ################################################################################################################
    // ###                                              Signatures                                                  ###
    // ################################################################################################################

    val isUsingCleartextSignatureFramework: Boolean
        get() = message.cleartextSigned

    val verifiedSignatures: List<SignatureVerification>
        get() = verifiedInlineSignatures.plus(verifiedDetachedSignatures)

    /**
     * List of all rejected signatures.
     */
    val rejectedSignatures: List<SignatureVerification.Failure>
        get() = mutableListOf<SignatureVerification.Failure>()
                .plus(rejectedInlineSignatures)
                .plus(rejectedDetachedSignatures)
                .toList()

    /**
     * List of all verified inline-signatures.
     * This list contains all acceptable, correct signatures that were part of the message itself.
     */
    val verifiedInlineSignatures: List<SignatureVerification> = verifiedInlineSignaturesByLayer
            .asSequence()
            .map { it.toMutableList() }
            .reduce { acc, signatureVerifications -> acc.addAll(signatureVerifications); acc }
            .toList()

    /**
     * [Iterator] of each [List] of verified inline-signatures of the message, separated by layer.
     * Since signatures might occur in different layers within a message, this method can be used to gain more detailed
     * insights into what signatures were encountered at what layers of the message structure.
     * Each item of the [Iterator] represents a layer of the message and contains only signatures from
     * this layer.
     * An empty list means no (or no acceptable) signatures were encountered in that layer.
     */
    val verifiedInlineSignaturesByLayer: Iterator<List<SignatureVerification>>
        get() = object : LayerIterator<List<SignatureVerification>>(message) {
            override fun matches(layer: Packet) = layer is Layer

            override fun getProperty(last: Layer): List<SignatureVerification> {
                return listOf<SignatureVerification>()
                        .plus(last.verifiedOnePassSignatures)
                        .plus(last.verifiedPrependedSignatures)
            }

        }

    /**
     * List of all rejected inline-signatures of the message.
     */
    val rejectedInlineSignatures: List<SignatureVerification.Failure> = rejectedInlineSignaturesByLayer
            .asSequence()
            .map { it.toMutableList() }
            .reduce { acc, failures -> acc.addAll(failures); acc}
            .toList()

    /**
     * Similar to [verifiedInlineSignaturesByLayer], this field contains all rejected inline-signatures
     * of the message, but organized by layer.
     */
    val rejectedInlineSignaturesByLayer: Iterator<List<SignatureVerification.Failure>>
        get() = object : LayerIterator<List<SignatureVerification.Failure>>(message) {
            override fun matches(layer: Packet) = layer is Layer

            override fun getProperty(last: Layer): List<SignatureVerification.Failure> =
                    mutableListOf<SignatureVerification.Failure>()
                            .plus(last.rejectedOnePassSignatures)
                            .plus(last.rejectedPrependedSignatures)
        }

    /**
     * List of all verified detached signatures.
     * This list contains all acceptable, correct detached signatures.
     */
    val verifiedDetachedSignatures: List<SignatureVerification> = message.verifiedDetachedSignatures

    /**
     * List of all rejected detached signatures.
     */
    val rejectedDetachedSignatures: List<SignatureVerification.Failure> = message.rejectedDetachedSignatures

    /**
     * True, if the message contains any (verified or rejected) signature, false if no signatures are present.
     */
    val hasSignature: Boolean
        get() = isVerifiedSigned() || hasRejectedSignatures()

    fun isVerifiedSigned(): Boolean = verifiedSignatures.isNotEmpty()

    fun hasRejectedSignatures(): Boolean = rejectedSignatures.isNotEmpty()

    /**
     * Return true, if the message was signed by a certificate for which we can authenticate a binding to the given userId.
     *
     * @param userId userId
     * @param email if true, treat the user-id as an email address and match all userIDs containing this address
     * @param certificateAuthority certificate authority
     * @param targetAmount targeted trust amount that needs to be reached by the binding to qualify as authenticated.
     *                     defaults to 120.
     * @return true, if we can authenticate a binding for a signing key with sufficient evidence
     */
    @JvmOverloads
    fun isAuthenticatablySignedBy(userId: String, email: Boolean, certificateAuthority: CertificateAuthority, targetAmount: Int = 120): Boolean {
        return verifiedSignatures.any {
            certificateAuthority.authenticateBinding(
                    it.signingKey.fingerprint, userId, email, it.signature.creationTime, targetAmount
            ).authenticated
        }
    }

    /**
     * Return rue, if the message was verifiable signed by a certificate that either has the given fingerprint
     * as primary key, or as the signing subkey.
     *
     * @param fingerprint fingerprint
     * @return true if message was signed by a cert identified by the given fingerprint
     */
    fun isVerifiedSignedBy(fingerprint: OpenPgpFingerprint) = verifiedSignatures.any {
        it.signingKey.primaryKeyFingerprint == fingerprint || it.signingKey.subkeyFingerprint == fingerprint
    }

    fun isVerifiedSignedBy(keys: PGPKeyRing) = containsSignatureBy(verifiedSignatures, keys)

    fun isVerifiedDetachedSignedBy(fingerprint: OpenPgpFingerprint) = verifiedDetachedSignatures.any {
        it.signingKey.primaryKeyFingerprint == fingerprint || it.signingKey.subkeyFingerprint == fingerprint
    }

    fun isVerifiedDetachedSignedBy(keys: PGPKeyRing) = containsSignatureBy(verifiedDetachedSignatures, keys)

    fun isVerifiedInlineSignedBy(fingerprint: OpenPgpFingerprint) = verifiedInlineSignatures.any {
        it.signingKey.primaryKeyFingerprint == fingerprint || it.signingKey.subkeyFingerprint == fingerprint
    }

    fun isVerifiedInlineSignedBy(keys: PGPKeyRing) = containsSignatureBy(verifiedInlineSignatures, keys)

    private fun containsSignatureBy(signatures: List<SignatureVerification>, keys: PGPKeyRing) =
            signatures.any {
                // Match certificate by primary key id
                keys.publicKey.keyID == it.signingKey.primaryKeyId &&
                        // match signing subkey
                        keys.getPublicKey(it.signingKey.subkeyId) != null
            }

    // ################################################################################################################
    // ###                                             Literal Data                                                 ###
    // ################################################################################################################

    /**
     * Value of the literal data packet's filename field.
     * This value can be used to store a decrypted file under its original filename,
     * but since this field is not necessarily part of the signed data of a message, usage of this field is
     * discouraged.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     */
    val filename: String? = findLiteralData()?.fileName

    /**
     * True, if the sender signals an increased degree of confidentiality by setting the filename of the literal
     * data packet to a special value that indicates that the data is intended for your eyes only.
     */
    @Deprecated("Reliance on this signaling mechanism is discouraged.")
    val isForYourEyesOnly: Boolean = PGPLiteralData.CONSOLE == filename

    /**
     * Value of the literal data packets modification date field.
     * This value can be used to restore the modification date of a decrypted file,
     * but since this field is not necessarily part of the signed data, its use is discouraged.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     */
    val modificationDate: Date? = findLiteralData()?.modificationDate

    /**
     * Value of the format field of the literal data packet.
     * This value indicates what format (text, binary data, ...) the data has.
     * Since this field is not necessarily part of the signed data of a message, its usage is discouraged.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     */
    val literalDataEncoding: StreamEncoding? = findLiteralData()?.format

    /**
     * Find the [LiteralData] layer of an OpenPGP message.
     * This method might return null, for example for a cleartext signed message without OpenPGP packets.
     *
     * @return literal data
     */
    private fun findLiteralData(): LiteralData? {
        // If the message is a non-OpenPGP message with a detached signature, or a Cleartext Signed message,
        // we might not have a Literal Data packet.
        var nested = message.child ?: return null

        while (nested.hasNestedChild()) {
            val layer = nested as Layer
            nested = checkNotNull(layer.child) {
                // Otherwise, we MUST find a Literal Data packet, or else the message is malformed
                "Malformed OpenPGP message. Cannot find Literal Data Packet"
            }
        }
        return nested as LiteralData
    }

    // ################################################################################################################
    // ###                                          Message Structure                                               ###
    // ################################################################################################################

    interface Packet

    interface Nested : Packet {
        fun hasNestedChild(): Boolean
    }

    abstract class Layer(
            val depth: Int
    ) : Packet {

        init {
            if (depth > MAX_LAYER_DEPTH) {
                throw MalformedOpenPgpMessageException("Maximum packet nesting depth ($MAX_LAYER_DEPTH) exceeded.")
            }
        }

        val verifiedDetachedSignatures: List<SignatureVerification> = mutableListOf()
        val rejectedDetachedSignatures: List<SignatureVerification.Failure> = mutableListOf()
        val verifiedOnePassSignatures: List<SignatureVerification> = mutableListOf()
        val rejectedOnePassSignatures: List<SignatureVerification.Failure> = mutableListOf()
        val verifiedPrependedSignatures: List<SignatureVerification> = mutableListOf()
        val rejectedPrependedSignatures: List<SignatureVerification.Failure> = mutableListOf()

        /**
         * Nested child element of this layer.
         * Might be `null`, if this layer does not have a child element
         * (e.g. if this is a [LiteralData] packet).
         */
        var child: Nested? = null

        fun addVerifiedDetachedSignature(signature: SignatureVerification) = apply {
            (verifiedDetachedSignatures as MutableList).add(signature)
        }

        fun addRejectedDetachedSignature(failure: SignatureVerification.Failure) = apply {
            (rejectedDetachedSignatures as MutableList).add(failure)
        }

        fun addVerifiedOnePassSignature(signature: SignatureVerification) = apply {
            (verifiedOnePassSignatures as MutableList).add(signature)
        }

        fun addRejectedOnePassSignature(failure: SignatureVerification.Failure) = apply {
            (rejectedOnePassSignatures as MutableList).add(failure)
        }

        fun addVerifiedPrependedSignature(signature: SignatureVerification) = apply {
            (verifiedPrependedSignatures as MutableList).add(signature)
        }

        fun addRejectedPrependedSignature(failure: SignatureVerification.Failure) = apply {
            (rejectedPrependedSignatures as MutableList).add(failure)
        }

        companion object {
            const val MAX_LAYER_DEPTH = 16
        }
    }

    /**
     * Outermost OpenPGP Message structure.
     *
     * @param cleartextSigned whether the message is using the Cleartext Signature Framework
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-7">RFC4880 §7. Cleartext Signature Framework</a>
     */
    class Message(var cleartextSigned: Boolean = false) : Layer(0) {
        fun setCleartextSigned() = apply { cleartextSigned = true }
    }

    /**
     * Literal Data Packet.
     *
     * @param fileName value of the filename field. An empty String represents no filename.
     * @param modificationDate value of the modification date field. The special value `Date(0)` indicates no
     * modification date.
     * @param format value of the format field.
     */
    class LiteralData(
            val fileName: String = "",
            val modificationDate: Date = Date(0L),
            val format: StreamEncoding = StreamEncoding.BINARY
    ) : Nested {

        // A literal data packet MUST NOT have a child element, as its content is the plaintext
        override fun hasNestedChild() = false
    }

    /**
     * Compressed Data Packet.
     *
     * @param algorithm [CompressionAlgorithm] used to compress the packet.
     * @param depth nesting depth at which this packet was encountered.
     */
    class CompressedData(
            val algorithm: CompressionAlgorithm,
            depth: Int) : Layer(depth), Nested {

        // A compressed data packet MUST have a child element
        override fun hasNestedChild() = true
    }

    /**
     * Encrypted Data.
     *
     * @param algorithm symmetric key algorithm used to encrypt the packet.
     * @param depth nesting depth at which this packet was encountered.
     */
    class EncryptedData(
            val algorithm: SymmetricKeyAlgorithm,
            depth: Int
    ) : Layer(depth), Nested {

        /**
         * [SessionKey] used to decrypt the packet.
         */
        var sessionKey: SessionKey? = null

        /**
         * List of all recipient key ids to which the packet was encrypted for.
         */
        val recipients: List<Long> = mutableListOf()

        fun addRecipients(keyIds: List<Long>) = apply {
            (recipients as MutableList).addAll(keyIds)
        }

        /**
         * Identifier of the subkey that was used to decrypt the packet (in case of a public key encrypted packet).
         */
        var decryptionKey: SubkeyIdentifier? = null

        // An encrypted data packet MUST have a child element
        override fun hasNestedChild() = true

    }

    /**
     * Iterator that iterates the packet structure from outermost to innermost packet, emitting the results of
     * a transformation ([getProperty]) on those packets that match ([matches]) a given criterion.
     *
     * @param message outermost structure object
     */
    private abstract class LayerIterator<O>(@Nonnull message: Message) : Iterator<O> {
        private var current: Nested?
        var last: Layer? = null
        var parent: Message?

        init {
            parent = message
            current = message.child
            current?.let {
                if (matches(it)) {
                    last = current as Layer
                }
            }
        }

        override fun hasNext(): Boolean {
            parent?.let {
                if (matches(it)) {
                    return true
                }
            }
            if (last == null) {
                findNext()
            }
            return last != null
        }

        override fun next(): O {
            parent?.let {
                if (matches(it)) {
                    return getProperty(it).also { parent = null }
                }
            }
            if (last == null) {
                findNext()
            }
            last?.let {
                return getProperty(it).also { last = null }
            }
            throw NoSuchElementException()
        }

        private fun findNext() {
            while (current != null && current is Layer) {
                current = (current as Layer).child
                if (current != null && matches(current!!)) {
                    last = current as Layer
                    break
                }
            }
        }

        abstract fun matches(layer: Packet): Boolean
        abstract fun getProperty(last: Layer): O
    }
}