// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import java.lang.IllegalArgumentException
import java.net.URL
import java.util.*
import kotlin.experimental.or
import openpgp.secondsTill
import openpgp.toSecondsPrecision
import org.bouncycastle.bcpg.SignatureSubpacket
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.*
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.pgpainless.algorithm.*
import org.pgpainless.key.util.RevocationAttributes

class SignatureSubpackets :
    BaseSignatureSubpackets,
    SelfSignatureSubpackets,
    CertificationSubpackets,
    RevocationSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<SignatureSubpackets>

    var signatureCreationTimeSubpacket: SignatureCreationTime? = null
    var signatureExpirationTimeSubpacket: SignatureExpirationTime? = null
    var issuerKeyIdSubpacket: IssuerKeyID? = null
    var issuerFingerprintSubpacket: IssuerFingerprint? = null
    val notationDataSubpackets: List<NotationData> = mutableListOf()
    val intendedRecipientFingerprintSubpackets: List<IntendedRecipientFingerprint> = mutableListOf()
    val revocationKeySubpackets: List<RevocationKey> = mutableListOf()
    var exportableSubpacket: Exportable? = null
    var signatureTargetSubpacket: SignatureTarget? = null
    var featuresSubpacket: Features? = null
    var keyFlagsSubpacket: KeyFlags? = null
    var trustSubpacket: TrustSignature? = null
    var preferredCompressionAlgorithmsSubpacket: PreferredAlgorithms? = null
    var preferredSymmetricKeyAlgorithmsSubpacket: PreferredAlgorithms? = null
    var preferredHashAlgorithmsSubpacket: PreferredAlgorithms? = null
    val embeddedSignatureSubpackets: List<EmbeddedSignature> = mutableListOf()
    var signerUserIdSubpacket: SignerUserID? = null
    var keyExpirationTimeSubpacket: KeyExpirationTime? = null
    var policyURISubpacket: PolicyURI? = null
    var primaryUserIdSubpacket: PrimaryUserID? = null
    var regularExpressionSubpacket: RegularExpression? = null
    var revocableSubpacket: Revocable? = null
    var revocationReasonSubpacket: RevocationReason? = null
    val residualSubpackets: List<SignatureSubpacket> = mutableListOf()

    companion object {

        @JvmStatic
        fun refreshHashedSubpackets(
            issuer: PGPPublicKey,
            oldSignature: PGPSignature
        ): SignatureSubpackets {
            return createHashedSubpacketsFrom(issuer, oldSignature.hashedSubPackets)
        }

        @JvmStatic
        fun refreshUnhashedSubpackets(oldSignature: PGPSignature): SignatureSubpackets {
            return createSubpacketsFrom(oldSignature.unhashedSubPackets)
        }

        @JvmStatic
        fun createHashedSubpacketsFrom(
            issuer: PGPPublicKey,
            base: PGPSignatureSubpacketVector
        ): SignatureSubpackets {
            return createSubpacketsFrom(base).apply { setIssuerFingerprintAndKeyId(issuer) }
        }

        @JvmStatic
        fun createSubpacketsFrom(base: PGPSignatureSubpacketVector): SignatureSubpackets {
            return SignatureSubpacketsHelper.applyFrom(base, SignatureSubpackets())
        }

        @JvmStatic
        fun createHashedSubpackets(issuer: PGPPublicKey): SignatureSubpackets {
            return createEmptySubpackets().setIssuerFingerprintAndKeyId(issuer)
        }

        @JvmStatic
        fun createEmptySubpackets(): SignatureSubpackets {
            return SignatureSubpackets()
        }
    }

    override fun setRevocationReason(
        revocationAttributes: RevocationAttributes
    ): SignatureSubpackets = apply { setRevocationReason(false, revocationAttributes) }

    override fun setRevocationReason(
        isCritical: Boolean,
        revocationAttributes: RevocationAttributes
    ): SignatureSubpackets = apply {
        setRevocationReason(
            isCritical, revocationAttributes.reason, revocationAttributes.description)
    }

    override fun setRevocationReason(
        isCritical: Boolean,
        reason: RevocationAttributes.Reason,
        description: CharSequence
    ): SignatureSubpackets = apply {
        setRevocationReason(RevocationReason(isCritical, reason.code, description.toString()))
    }

    override fun setRevocationReason(reason: RevocationReason?): SignatureSubpackets = apply {
        this.revocationReasonSubpacket = reason
    }

    override fun setKeyFlags(vararg keyflags: KeyFlag): SignatureSubpackets = apply {
        setKeyFlags(true, *keyflags)
    }

    override fun setKeyFlags(keyFlags: List<KeyFlag>): SignatureSubpackets = apply {
        setKeyFlags(true, *keyFlags.toTypedArray())
    }

    override fun setKeyFlags(isCritical: Boolean, vararg keyFlags: KeyFlag): SignatureSubpackets =
        apply {
            setKeyFlags(KeyFlags(isCritical, KeyFlag.toBitmask(*keyFlags)))
        }

    override fun setKeyFlags(keyFlags: KeyFlags?): SignatureSubpackets = apply {
        this.keyFlagsSubpacket = keyFlags
    }

    override fun setPrimaryUserId(): SignatureSubpackets = apply { setPrimaryUserId(true) }

    override fun setPrimaryUserId(isCritical: Boolean): SignatureSubpackets = apply {
        setPrimaryUserId(PrimaryUserID(isCritical, true))
    }

    override fun setPrimaryUserId(primaryUserID: PrimaryUserID?): SignatureSubpackets = apply {
        this.primaryUserIdSubpacket = primaryUserID
    }

    override fun setKeyExpirationTime(
        key: PGPPublicKey,
        keyExpirationTime: Date?
    ): SignatureSubpackets = apply { setKeyExpirationTime(key.creationTime, keyExpirationTime) }

    override fun setKeyExpirationTime(
        keyCreationTime: Date,
        keyExpirationTime: Date?
    ): SignatureSubpackets = apply {
        setKeyExpirationTime(true, keyCreationTime, keyExpirationTime)
    }

    override fun setKeyExpirationTime(
        isCritical: Boolean,
        keyCreationTime: Date,
        keyExpirationTime: Date?
    ): SignatureSubpackets = apply {
        if (keyExpirationTime == null) {
            setKeyExpirationTime(isCritical, 0)
        } else {
            setKeyExpirationTime(isCritical, keyCreationTime.secondsTill(keyExpirationTime))
        }
    }

    override fun setKeyExpirationTime(
        isCritical: Boolean,
        secondsFromCreationToExpiration: Long
    ): SignatureSubpackets = apply {
        enforceExpirationBounds(secondsFromCreationToExpiration)
        setKeyExpirationTime(KeyExpirationTime(isCritical, secondsFromCreationToExpiration))
    }

    override fun setKeyExpirationTime(keyExpirationTime: KeyExpirationTime?): SignatureSubpackets =
        apply {
            this.keyExpirationTimeSubpacket = keyExpirationTime
        }

    override fun setPreferredCompressionAlgorithms(
        vararg algorithms: CompressionAlgorithm
    ): SignatureSubpackets = apply { setPreferredCompressionAlgorithms(setOf(*algorithms)) }

    override fun setPreferredCompressionAlgorithms(
        algorithms: Collection<CompressionAlgorithm>
    ): SignatureSubpackets = apply { setPreferredCompressionAlgorithms(false, algorithms) }

    override fun setPreferredCompressionAlgorithms(
        isCritical: Boolean,
        algorithms: Collection<CompressionAlgorithm>
    ): SignatureSubpackets = apply {
        setPreferredCompressionAlgorithms(
            PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_COMP_ALGS,
                isCritical,
                algorithms.map { it.algorithmId }.toIntArray()))
    }

    override fun setPreferredCompressionAlgorithms(
        algorithms: PreferredAlgorithms?
    ): SignatureSubpackets = apply {
        require(
            algorithms == null || algorithms.type == SignatureSubpacketTags.PREFERRED_COMP_ALGS) {
                "Invalid preferred compression algorithms type."
            }
        this.preferredCompressionAlgorithmsSubpacket = algorithms
    }

    override fun setPreferredSymmetricKeyAlgorithms(
        vararg algorithms: SymmetricKeyAlgorithm
    ): SignatureSubpackets = apply { setPreferredSymmetricKeyAlgorithms(setOf(*algorithms)) }

    override fun setPreferredSymmetricKeyAlgorithms(
        algorithms: Collection<SymmetricKeyAlgorithm>
    ): SignatureSubpackets = apply { setPreferredSymmetricKeyAlgorithms(false, algorithms) }

    override fun setPreferredSymmetricKeyAlgorithms(
        isCritical: Boolean,
        algorithms: Collection<SymmetricKeyAlgorithm>
    ): SignatureSubpackets = apply {
        setPreferredSymmetricKeyAlgorithms(
            PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_SYM_ALGS,
                isCritical,
                algorithms.map { it.algorithmId }.toIntArray()))
    }

    override fun setPreferredSymmetricKeyAlgorithms(
        algorithms: PreferredAlgorithms?
    ): SignatureSubpackets = apply {
        require(
            algorithms == null || algorithms.type == SignatureSubpacketTags.PREFERRED_SYM_ALGS) {
                "Invalid preferred symmetric algorithms type."
            }
        this.preferredSymmetricKeyAlgorithmsSubpacket = algorithms
    }

    override fun setPreferredHashAlgorithms(vararg algorithms: HashAlgorithm): SignatureSubpackets =
        apply {
            setPreferredHashAlgorithms(setOf(*algorithms))
        }

    override fun setPreferredHashAlgorithms(
        algorithms: Collection<HashAlgorithm>
    ): SignatureSubpackets = apply { setPreferredHashAlgorithms(false, algorithms) }

    override fun setPreferredHashAlgorithms(
        isCritical: Boolean,
        algorithms: Collection<HashAlgorithm>
    ): SignatureSubpackets = apply {
        setPreferredHashAlgorithms(
            PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_HASH_ALGS,
                isCritical,
                algorithms.map { it.algorithmId }.toIntArray()))
    }

    override fun setPreferredHashAlgorithms(algorithms: PreferredAlgorithms?): SignatureSubpackets =
        apply {
            require(
                algorithms == null ||
                    algorithms.type == SignatureSubpacketTags.PREFERRED_HASH_ALGS) {
                    "Invalid preferred hash algorithms type."
                }
            this.preferredHashAlgorithmsSubpacket = algorithms
        }

    override fun addRevocationKey(revocationKey: PGPPublicKey): SignatureSubpackets = apply {
        addRevocationKey(true, revocationKey)
    }

    override fun addRevocationKey(
        isCritical: Boolean,
        revocationKey: PGPPublicKey
    ): SignatureSubpackets = apply { addRevocationKey(isCritical, false, revocationKey) }

    override fun addRevocationKey(
        isCritical: Boolean,
        isSensitive: Boolean,
        revocationKey: PGPPublicKey
    ): SignatureSubpackets = apply {
        val clazz = 0x80.toByte() or if (isSensitive) 0x40.toByte() else 0x00.toByte()
        addRevocationKey(
            RevocationKey(isCritical, clazz, revocationKey.algorithm, revocationKey.fingerprint))
    }

    override fun addRevocationKey(revocationKey: RevocationKey): SignatureSubpackets = apply {
        (this.revocationKeySubpackets as MutableList).add(revocationKey)
    }

    override fun clearRevocationKeys(): SignatureSubpackets = apply {
        (this.revocationKeySubpackets as MutableList).clear()
    }

    override fun setFeatures(vararg features: Feature): SignatureSubpackets = apply {
        setFeatures(true, *features)
    }

    override fun setFeatures(isCritical: Boolean, vararg features: Feature): SignatureSubpackets =
        apply {
            setFeatures(Features(isCritical, Feature.toBitmask(*features)))
        }

    override fun setFeatures(features: Features?): SignatureSubpackets = apply {
        this.featuresSubpacket = features
    }

    override fun setIssuerFingerprintAndKeyId(key: PGPPublicKey): SignatureSubpackets = apply {
        setIssuerKeyId(key.keyID)
        setIssuerFingerprint(key)
    }

    override fun setIssuerKeyId(keyId: Long): SignatureSubpackets = apply {
        setIssuerKeyId(false, keyId)
    }

    override fun setIssuerKeyId(isCritical: Boolean, keyId: Long): SignatureSubpackets = apply {
        setIssuerKeyId(IssuerKeyID(isCritical, keyId))
    }

    override fun setIssuerKeyId(issuerKeyID: IssuerKeyID?): SignatureSubpackets = apply {
        this.issuerKeyIdSubpacket = issuerKeyID
    }

    override fun setIssuerFingerprint(
        isCritical: Boolean,
        issuer: PGPPublicKey
    ): SignatureSubpackets = apply {
        setIssuerFingerprint(IssuerFingerprint(isCritical, issuer.version, issuer.fingerprint))
    }

    override fun setIssuerFingerprint(issuer: PGPPublicKey): SignatureSubpackets = apply {
        setIssuerFingerprint(false, issuer)
    }

    override fun setIssuerFingerprint(fingerprint: IssuerFingerprint?): SignatureSubpackets =
        apply {
            this.issuerFingerprintSubpacket = fingerprint
        }

    override fun setSignatureCreationTime(creationTime: Date): SignatureSubpackets = apply {
        setSignatureCreationTime(true, creationTime)
    }

    override fun setSignatureCreationTime(
        isCritical: Boolean,
        creationTime: Date
    ): SignatureSubpackets = apply {
        setSignatureCreationTime(SignatureCreationTime(isCritical, creationTime))
    }

    override fun setSignatureCreationTime(
        creationTime: SignatureCreationTime?
    ): SignatureSubpackets = apply { this.signatureCreationTimeSubpacket = creationTime }

    override fun setSignatureExpirationTime(
        creationTime: Date,
        expirationTime: Date?
    ): SignatureSubpackets = apply {
        setSignatureExpirationTime(true, creationTime, expirationTime)
    }

    override fun setSignatureExpirationTime(
        isCritical: Boolean,
        creationTime: Date,
        expirationTime: Date?
    ): SignatureSubpackets = apply {
        if (expirationTime != null) {
            require(creationTime.toSecondsPrecision() < expirationTime.toSecondsPrecision()) {
                "Expiration time MUST NOT be less or equal the creation time."
            }
            setSignatureExpirationTime(
                SignatureExpirationTime(isCritical, creationTime.secondsTill(expirationTime)))
        } else {
            setSignatureExpirationTime(SignatureExpirationTime(isCritical, 0))
        }
    }

    override fun setSignatureExpirationTime(
        isCritical: Boolean,
        seconds: Long
    ): SignatureSubpackets = apply {
        enforceExpirationBounds(seconds)
        setSignatureExpirationTime(SignatureExpirationTime(isCritical, seconds))
    }

    /**
     * Enforce that <pre>seconds</pre> is within bounds of an unsigned 32bit number. Values less
     * than 0 are illegal, as well as values greater 0xffffffff.
     *
     * @param seconds number to check
     * @throws IllegalArgumentException in case of an under- or overflow
     */
    private fun enforceExpirationBounds(seconds: Long) {
        require(seconds <= 0xffffffffL) {
            "Integer overflow. Seconds from creation to expiration (${seconds}) cannot be larger than ${0xffffffffL}."
        }
        require(seconds >= 0) { "Seconds from creation to expiration cannot be less than 0." }
    }

    override fun setSignatureExpirationTime(
        expirationTime: SignatureExpirationTime?
    ): SignatureSubpackets = apply { this.signatureExpirationTimeSubpacket = expirationTime }

    override fun setSignerUserId(userId: CharSequence): SignatureSubpackets = apply {
        setSignerUserId(false, userId)
    }

    override fun setSignerUserId(isCritical: Boolean, userId: CharSequence): SignatureSubpackets =
        apply {
            setSignerUserId(SignerUserID(isCritical, userId.toString()))
        }

    override fun setSignerUserId(signerUserID: SignerUserID?): SignatureSubpackets = apply {
        this.signerUserIdSubpacket = signerUserID
    }

    override fun addNotationData(
        isCritical: Boolean,
        notationName: String,
        notationValue: String
    ): SignatureSubpackets = apply {
        addNotationData(isCritical, true, notationName, notationValue)
    }

    override fun addNotationData(
        isCritical: Boolean,
        isHumanReadable: Boolean,
        notationName: String,
        notationValue: String
    ): SignatureSubpackets = apply {
        addNotationData(NotationData(isCritical, isHumanReadable, notationName, notationValue))
    }

    override fun addNotationData(notationData: NotationData): SignatureSubpackets = apply {
        (this.notationDataSubpackets as MutableList).add(notationData)
    }

    override fun clearNotationData(): SignatureSubpackets = apply {
        (this.notationDataSubpackets as MutableList).clear()
    }

    override fun addIntendedRecipientFingerprint(recipientKey: PGPPublicKey): SignatureSubpackets =
        apply {
            addIntendedRecipientFingerprint(false, recipientKey)
        }

    override fun addIntendedRecipientFingerprint(
        isCritical: Boolean,
        recipientKey: PGPPublicKey
    ): SignatureSubpackets = apply {
        addIntendedRecipientFingerprint(
            IntendedRecipientFingerprint(
                isCritical, recipientKey.version, recipientKey.fingerprint))
    }

    override fun addIntendedRecipientFingerprint(
        intendedRecipient: IntendedRecipientFingerprint
    ): SignatureSubpackets = apply {
        (this.intendedRecipientFingerprintSubpackets as MutableList).add(intendedRecipient)
    }

    override fun clearIntendedRecipientFingerprints(): SignatureSubpackets = apply {
        (this.intendedRecipientFingerprintSubpackets as MutableList).clear()
    }

    override fun setExportable(): SignatureSubpackets = apply { setExportable(true) }

    override fun setExportable(isExportable: Boolean): SignatureSubpackets = apply {
        setExportable(true, isExportable)
    }

    override fun setExportable(isCritical: Boolean, isExportable: Boolean): SignatureSubpackets =
        apply {
            setExportable(Exportable(isCritical, isExportable))
        }

    override fun setExportable(exportable: Exportable?): SignatureSubpackets = apply {
        this.exportableSubpacket = exportable
    }

    override fun setPolicyUrl(policyUrl: URL): SignatureSubpackets = apply {
        setPolicyUrl(false, policyUrl)
    }

    override fun setPolicyUrl(isCritical: Boolean, policyUrl: URL): SignatureSubpackets = apply {
        setPolicyUrl(PolicyURI(isCritical, policyUrl.toString()))
    }

    override fun setPolicyUrl(policyUrl: PolicyURI?): SignatureSubpackets = apply {
        this.policyURISubpacket = policyURISubpacket
    }

    override fun setRegularExpression(regex: CharSequence): SignatureSubpackets = apply {
        setRegularExpression(false, regex)
    }

    override fun setRegularExpression(
        isCritical: Boolean,
        regex: CharSequence
    ): SignatureSubpackets = apply {
        setRegularExpression(RegularExpression(isCritical, regex.toString()))
    }

    override fun setRegularExpression(regex: RegularExpression?): SignatureSubpackets = apply {
        this.regularExpressionSubpacket = regex
    }

    override fun setRevocable(): SignatureSubpackets = apply { setRevocable(true) }

    override fun setRevocable(isRevocable: Boolean): SignatureSubpackets = apply {
        setRevocable(true, isRevocable)
    }

    override fun setRevocable(isCritical: Boolean, isRevocable: Boolean): SignatureSubpackets =
        apply {
            setRevocable(Revocable(isCritical, isRevocable))
        }

    override fun setRevocable(revocable: Revocable?): SignatureSubpackets = apply {
        this.revocableSubpacket = revocable
    }

    override fun setSignatureTarget(
        keyAlgorithm: PublicKeyAlgorithm,
        hashAlgorithm: HashAlgorithm,
        hashData: ByteArray
    ): SignatureSubpackets = apply {
        setSignatureTarget(true, keyAlgorithm, hashAlgorithm, hashData)
    }

    override fun setSignatureTarget(
        isCritical: Boolean,
        keyAlgorithm: PublicKeyAlgorithm,
        hashAlgorithm: HashAlgorithm,
        hashData: ByteArray
    ): SignatureSubpackets = apply {
        setSignatureTarget(
            SignatureTarget(
                isCritical, keyAlgorithm.algorithmId, hashAlgorithm.algorithmId, hashData))
    }

    override fun setSignatureTarget(signatureTarget: SignatureTarget?): SignatureSubpackets =
        apply {
            this.signatureTargetSubpacket = signatureTarget
        }

    override fun setTrust(depth: Int, amount: Int): SignatureSubpackets = apply {
        setTrust(true, depth, amount)
    }

    override fun setTrust(isCritical: Boolean, depth: Int, amount: Int): SignatureSubpackets =
        apply {
            setTrust(TrustSignature(isCritical, depth, amount))
        }

    override fun setTrust(trust: TrustSignature?): SignatureSubpackets = apply {
        this.trustSubpacket = trust
    }

    override fun addEmbeddedSignature(signature: PGPSignature): SignatureSubpackets = apply {
        addEmbeddedSignature(true, signature)
    }

    override fun addEmbeddedSignature(
        isCritical: Boolean,
        signature: PGPSignature
    ): SignatureSubpackets = apply {
        val sig = signature.encoded
        val data =
            if (sig.size - 1 > 256) {
                ByteArray(sig.size - 3)
            } else {
                ByteArray(sig.size - 2)
            }
        System.arraycopy(sig, sig.size - data.size, data, 0, data.size)
        addEmbeddedSignature(EmbeddedSignature(isCritical, false, data))
    }

    override fun addEmbeddedSignature(embeddedSignature: EmbeddedSignature): SignatureSubpackets =
        apply {
            (this.embeddedSignatureSubpackets as MutableList).add(embeddedSignature)
        }

    override fun clearEmbeddedSignatures(): SignatureSubpackets = apply {
        (this.embeddedSignatureSubpackets as MutableList).clear()
    }

    fun addResidualSubpacket(
        subpacket: org.bouncycastle.bcpg.SignatureSubpacket
    ): SignatureSubpackets = apply { (residualSubpackets as MutableList).add(subpacket) }
}
