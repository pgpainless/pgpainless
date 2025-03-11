// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import java.io.IOException
import java.net.URL
import java.util.*
import org.bouncycastle.bcpg.sig.*
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.algorithm.PublicKeyAlgorithm

interface BaseSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<BaseSignatureSubpackets>

    fun setAppropriateIssuerInfo(key: OpenPGPComponentKey): BaseSignatureSubpackets

    fun setAppropriateIssuerInfo(key: PGPPublicKey): BaseSignatureSubpackets

    /**
     * Depending on the given [version], use the appropriate means of setting issuer information. V6
     * signatures for example MUST NOT contain an [IssuerKeyID] packet.
     *
     * @param key issuer key
     * @param version signature version
     * @return this
     */
    fun setAppropriateIssuerInfo(
        key: PGPPublicKey,
        version: OpenPGPKeyVersion
    ): BaseSignatureSubpackets

    /**
     * Add both an [IssuerKeyID] and [IssuerFingerprint] subpacket pointing to the given key.
     *
     * @param key key
     * @return this
     * @deprecated this method MUST NOT be used for OpenPGP v6, since v6 signatures MUST NOT contain
     *   any [IssuerKeyID] packets.
     */
    fun setIssuerFingerprintAndKeyId(key: PGPPublicKey): BaseSignatureSubpackets

    fun setIssuerKeyId(keyId: Long): BaseSignatureSubpackets

    fun setIssuerKeyId(isCritical: Boolean, keyId: Long): BaseSignatureSubpackets

    fun setIssuerKeyId(issuerKeyID: IssuerKeyID?): BaseSignatureSubpackets

    fun setIssuerFingerprint(isCritical: Boolean, issuer: PGPPublicKey): BaseSignatureSubpackets

    fun setIssuerFingerprint(issuer: PGPPublicKey): BaseSignatureSubpackets

    fun setIssuerFingerprint(fingerprint: IssuerFingerprint?): BaseSignatureSubpackets

    fun setSignatureCreationTime(creationTime: Date): BaseSignatureSubpackets

    fun setSignatureCreationTime(isCritical: Boolean, creationTime: Date): BaseSignatureSubpackets

    fun setSignatureCreationTime(creationTime: SignatureCreationTime?): BaseSignatureSubpackets

    fun setSignatureExpirationTime(
        creationTime: Date,
        expirationTime: Date?
    ): BaseSignatureSubpackets

    fun setSignatureExpirationTime(
        isCritical: Boolean,
        creationTime: Date,
        expirationTime: Date?
    ): BaseSignatureSubpackets

    fun setSignatureExpirationTime(isCritical: Boolean, seconds: Long): BaseSignatureSubpackets

    fun setSignatureExpirationTime(
        expirationTime: SignatureExpirationTime?
    ): BaseSignatureSubpackets

    @Deprecated("Usage of subpacket is discouraged")
    fun setSignerUserId(userId: CharSequence): BaseSignatureSubpackets

    @Deprecated("Usage of subpacket is discouraged")
    fun setSignerUserId(isCritical: Boolean, userId: CharSequence): BaseSignatureSubpackets

    @Deprecated("Usage of subpacket is discouraged")
    fun setSignerUserId(signerUserID: SignerUserID?): BaseSignatureSubpackets

    fun addNotationData(
        isCritical: Boolean,
        notationName: String,
        notationValue: String
    ): BaseSignatureSubpackets

    fun addNotationData(
        isCritical: Boolean,
        isHumanReadable: Boolean,
        notationName: String,
        notationValue: String
    ): BaseSignatureSubpackets

    fun addNotationData(notationData: NotationData): BaseSignatureSubpackets

    fun clearNotationData(): BaseSignatureSubpackets

    fun addIntendedRecipientFingerprint(recipientKey: PGPPublicKey): BaseSignatureSubpackets

    fun addIntendedRecipientFingerprint(
        isCritical: Boolean,
        recipientKey: PGPPublicKey
    ): BaseSignatureSubpackets

    fun addIntendedRecipientFingerprint(
        intendedRecipient: IntendedRecipientFingerprint
    ): BaseSignatureSubpackets

    fun clearIntendedRecipientFingerprints(): BaseSignatureSubpackets

    fun setExportable(): BaseSignatureSubpackets

    fun setExportable(isExportable: Boolean): BaseSignatureSubpackets

    fun setExportable(isCritical: Boolean, isExportable: Boolean): BaseSignatureSubpackets

    fun setExportable(exportable: Exportable?): BaseSignatureSubpackets

    fun setPolicyUrl(policyUrl: URL): BaseSignatureSubpackets

    fun setPolicyUrl(isCritical: Boolean, policyUrl: URL): BaseSignatureSubpackets

    fun setPolicyUrl(policyUrl: PolicyURI?): BaseSignatureSubpackets

    fun setRegularExpression(regex: CharSequence): BaseSignatureSubpackets

    fun setRegularExpression(isCritical: Boolean, regex: CharSequence): BaseSignatureSubpackets

    fun setRegularExpression(regex: RegularExpression?): BaseSignatureSubpackets

    fun setRevocable(): BaseSignatureSubpackets

    fun setRevocable(isRevocable: Boolean): BaseSignatureSubpackets

    fun setRevocable(isCritical: Boolean, isRevocable: Boolean): BaseSignatureSubpackets

    fun setRevocable(revocable: Revocable?): BaseSignatureSubpackets

    fun setSignatureTarget(
        keyAlgorithm: PublicKeyAlgorithm,
        hashAlgorithm: HashAlgorithm,
        hashData: ByteArray
    ): BaseSignatureSubpackets

    fun setSignatureTarget(
        isCritical: Boolean,
        keyAlgorithm: PublicKeyAlgorithm,
        hashAlgorithm: HashAlgorithm,
        hashData: ByteArray
    ): BaseSignatureSubpackets

    fun setSignatureTarget(signatureTarget: SignatureTarget?): BaseSignatureSubpackets

    fun setTrust(depth: Int, amount: Int): BaseSignatureSubpackets

    fun setTrust(isCritical: Boolean, depth: Int, amount: Int): BaseSignatureSubpackets

    fun setTrust(trust: TrustSignature?): BaseSignatureSubpackets

    @Throws(IOException::class)
    fun addEmbeddedSignature(signature: PGPSignature): BaseSignatureSubpackets

    @Throws(IOException::class)
    fun addEmbeddedSignature(isCritical: Boolean, signature: PGPSignature): BaseSignatureSubpackets

    fun addEmbeddedSignature(embeddedSignature: EmbeddedSignature): BaseSignatureSubpackets

    fun clearEmbeddedSignatures(): BaseSignatureSubpackets

    companion object {

        /** Factory method for a [Callback] that does nothing. */
        @JvmStatic fun nop() = object : Callback {}

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the hashed
         * subpacket area of a [BaseSignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = BaseSignatureSubpackets.applyHashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyHashed(function: BaseSignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: BaseSignatureSubpackets) {
                    function(hashedSubpackets)
                }
            }
        }

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the unhashed
         * subpacket area of a [BaseSignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = BaseSignatureSubpackets.applyUnhashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyUnhashed(function: BaseSignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyUnhashedSubpackets(unhashedSubpackets: BaseSignatureSubpackets) {
                    function(unhashedSubpackets)
                }
            }
        }
    }
}
