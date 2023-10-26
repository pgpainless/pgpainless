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
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm

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

    fun setSignerUserId(userId: CharSequence): BaseSignatureSubpackets

    fun setSignerUserId(isCritical: Boolean, userId: CharSequence): BaseSignatureSubpackets

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
}
