// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import java.io.IOException
import java.net.URL
import java.time.Duration
import java.util.*
import openpgp.plusSeconds
import org.bouncycastle.bcpg.sig.*
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.OpenPgpFingerprint

interface BaseSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<BaseSignatureSubpackets>

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

    fun getIssuerKeyId(): Long? = getIssuerKeyIdPacket()?.keyID

    fun getIssuerKeyIdPacket(): IssuerKeyID?

    fun setIssuerFingerprint(isCritical: Boolean, issuer: PGPPublicKey): BaseSignatureSubpackets

    fun setIssuerFingerprint(issuer: PGPPublicKey): BaseSignatureSubpackets

    fun setIssuerFingerprint(fingerprint: IssuerFingerprint?): BaseSignatureSubpackets

    fun getIssuerFingerprint(): OpenPgpFingerprint? =
        getIssuerFingerprintPacket()?.let { OpenPgpFingerprint.of(it.keyVersion, it.fingerprint) }

    fun getIssuerFingerprintPacket(): IssuerFingerprint?

    fun setSignatureCreationTime(creationTime: Date): BaseSignatureSubpackets

    fun setSignatureCreationTime(isCritical: Boolean, creationTime: Date): BaseSignatureSubpackets

    fun setSignatureCreationTime(creationTime: SignatureCreationTime?): BaseSignatureSubpackets

    fun getSignatureCreationTime(): Date? = getSignatureCreationTimePacket()?.time

    fun getSignatureCreationTimePacket(): SignatureCreationTime?

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
        isCritical: Boolean,
        duration: Duration
    ): BaseSignatureSubpackets {
        require(!duration.isNegative) { "Signature Expiration Time cannot be negative." }
        return setSignatureExpirationTime(isCritical, duration.seconds)
    }

    fun setSignatureExpirationTime(
        expirationTime: SignatureExpirationTime?
    ): BaseSignatureSubpackets

    fun getSignatureExpirationTimeInSeconds(): Long? = getSignatureExpirationTimePacket()?.time

    fun getSignatureExpirationTime(creationTime: Date): Date? =
        getSignatureExpirationTimeInSeconds()?.let {
            if (it == 0L) {
                null
            } else {
                creationTime.plusSeconds(it)
            }
        }

    fun getSignatureExpirationTimePacket(): SignatureExpirationTime?

    fun setSignerUserId(userId: CharSequence): BaseSignatureSubpackets

    fun setSignerUserId(isCritical: Boolean, userId: CharSequence): BaseSignatureSubpackets

    fun setSignerUserId(signerUserID: SignerUserID?): BaseSignatureSubpackets

    fun getSignerUserId(): CharSequence? = getSignerUserIdPacket()?.id

    fun getSignerUserIdPacket(): SignerUserID?

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

    fun getNotationDataPackets(): List<NotationData>

    fun clearNotationData(): BaseSignatureSubpackets

    fun addIntendedRecipientFingerprint(recipientKey: PGPPublicKey): BaseSignatureSubpackets

    fun addIntendedRecipientFingerprint(
        isCritical: Boolean,
        recipientKey: PGPPublicKey
    ): BaseSignatureSubpackets

    fun addIntendedRecipientFingerprint(
        intendedRecipient: IntendedRecipientFingerprint
    ): BaseSignatureSubpackets

    fun getIntendedRecipientFingerprints(): List<OpenPgpFingerprint> =
        getIntendedRecipientFingerprintPackets().map {
            OpenPgpFingerprint.of(it.keyVersion, it.fingerprint)
        }

    fun getIntendedRecipientFingerprintPackets(): List<IntendedRecipientFingerprint>

    fun clearIntendedRecipientFingerprints(): BaseSignatureSubpackets

    fun setExportable(): BaseSignatureSubpackets

    fun setExportable(isExportable: Boolean): BaseSignatureSubpackets

    fun setExportable(isCritical: Boolean, isExportable: Boolean): BaseSignatureSubpackets

    fun setExportable(exportable: Exportable?): BaseSignatureSubpackets

    fun getExportable(): Boolean? = getExportablePacket()?.isExportable

    fun getExportablePacket(): Exportable?

    fun setPolicyUrl(policyUrl: URL): BaseSignatureSubpackets

    fun setPolicyUrl(isCritical: Boolean, policyUrl: URL): BaseSignatureSubpackets

    fun setPolicyUrl(policyUrl: PolicyURI?): BaseSignatureSubpackets

    fun getPolicyUrl(): CharSequence? = getPolicyUrlPacket()?.uri

    fun getPolicyUrlPacket(): PolicyURI?

    fun setRegularExpression(regex: CharSequence): BaseSignatureSubpackets

    fun setRegularExpression(isCritical: Boolean, regex: CharSequence): BaseSignatureSubpackets

    fun setRegularExpression(regex: RegularExpression?): BaseSignatureSubpackets

    fun getRegularExpression(): CharSequence? = getRegularExpressionPacket()?.regex

    fun getRegularExpressionPacket(): RegularExpression?

    fun setRevocable(): BaseSignatureSubpackets

    fun setRevocable(isRevocable: Boolean): BaseSignatureSubpackets

    fun setRevocable(isCritical: Boolean, isRevocable: Boolean): BaseSignatureSubpackets

    fun setRevocable(revocable: Revocable?): BaseSignatureSubpackets

    fun getRevocable(): Boolean? = getRevocablePacket()?.isRevocable

    fun getRevocablePacket(): Revocable?

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

    fun getSignatureTargetPacket(): SignatureTarget?

    fun setTrust(depth: Int, amount: Int): BaseSignatureSubpackets

    fun setTrust(isCritical: Boolean, depth: Int, amount: Int): BaseSignatureSubpackets

    fun setTrust(trust: TrustSignature?): BaseSignatureSubpackets

    fun getTrustPacket(): TrustSignature?

    @Throws(IOException::class)
    fun addEmbeddedSignature(signature: PGPSignature): BaseSignatureSubpackets

    @Throws(IOException::class)
    fun addEmbeddedSignature(isCritical: Boolean, signature: PGPSignature): BaseSignatureSubpackets

    fun addEmbeddedSignature(embeddedSignature: EmbeddedSignature): BaseSignatureSubpackets

    fun getEmbeddedSignaturePackets(): List<EmbeddedSignature>

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
