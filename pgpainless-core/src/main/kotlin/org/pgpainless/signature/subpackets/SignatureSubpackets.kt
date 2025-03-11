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
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.*
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.pgpainless.algorithm.*
import org.pgpainless.key.util.RevocationAttributes

class SignatureSubpackets(
    val subpacketsGenerator: PGPSignatureSubpacketGenerator = PGPSignatureSubpacketGenerator()
) :
    BaseSignatureSubpackets,
    SelfSignatureSubpackets,
    CertificationSubpackets,
    RevocationSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<SignatureSubpackets>

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
            return createSubpacketsFrom(base).apply { setAppropriateIssuerInfo(issuer) }
        }

        @JvmStatic
        fun createSubpacketsFrom(base: PGPSignatureSubpacketVector): SignatureSubpackets {
            return SignatureSubpackets(PGPSignatureSubpacketGenerator(base)).apply {
                subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.ISSUER_KEY_ID)
                subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.ISSUER_FINGERPRINT)
                subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.CREATION_TIME)
            }
        }

        @JvmStatic
        fun createHashedSubpackets(issuer: PGPPublicKey): SignatureSubpackets {
            return createEmptySubpackets().setAppropriateIssuerInfo(issuer)
        }

        @JvmStatic
        fun createEmptySubpackets(): SignatureSubpackets {
            return SignatureSubpackets(PGPSignatureSubpacketGenerator())
        }

        /** Factory method for a [Callback] that does nothing. */
        @JvmStatic fun nop() = object : Callback {}

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the hashed
         * subpacket area of a [SignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = SignatureSubpackets.applyHashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyHashed(function: SignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SignatureSubpackets) {
                    function(hashedSubpackets)
                }
            }
        }

        /**
         * Factory function with receiver, which returns a [Callback] that modifies the unhashed
         * subpacket area of a [SignatureSubpackets] object.
         *
         * Can be called like this:
         * ```
         * val callback = SignatureSubpackets.applyUnhashed {
         *     setCreationTime(date)
         *     ...
         * }
         * ```
         */
        @JvmStatic
        fun applyUnhashed(function: SignatureSubpackets.() -> Unit): Callback {
            return object : Callback {
                override fun modifyUnhashedSubpackets(unhashedSubpackets: SignatureSubpackets) {
                    function(unhashedSubpackets)
                }
            }
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
        reason?.let {
            subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.REVOCATION_REASON)
            subpacketsGenerator.setRevocationReason(
                it.isCritical, it.revocationReason, it.revocationDescription)
        }
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
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS)
        keyFlags?.let { subpacketsGenerator.setKeyFlags(it.isCritical, it.flags) }
    }

    override fun setPrimaryUserId(): SignatureSubpackets = apply { setPrimaryUserId(true) }

    override fun setPrimaryUserId(isCritical: Boolean): SignatureSubpackets = apply {
        setPrimaryUserId(PrimaryUserID(isCritical, true))
    }

    override fun setPrimaryUserId(primaryUserID: PrimaryUserID?): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.PRIMARY_USER_ID)
        primaryUserID?.let {
            subpacketsGenerator.setPrimaryUserID(it.isCritical, it.isPrimaryUserID)
        }
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
            subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.KEY_EXPIRE_TIME)
            keyExpirationTime?.let {
                subpacketsGenerator.setKeyExpirationTime(it.isCritical, it.time)
            }
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
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.PREFERRED_COMP_ALGS)
        algorithms?.let {
            subpacketsGenerator.setPreferredCompressionAlgorithms(it.isCritical, it.preferences)
        }
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
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS)
        algorithms?.let {
            subpacketsGenerator.setPreferredSymmetricAlgorithms(it.isCritical, it.preferences)
        }
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
            subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.PREFERRED_HASH_ALGS)
            algorithms?.let {
                subpacketsGenerator.setPreferredHashAlgorithms(it.isCritical, it.preferences)
            }
        }

    override fun setPreferredAEADCiphersuites(
        aeadAlgorithms: Collection<AEADCipherMode>
    ): SignatureSubpackets =
        setPreferredAEADCiphersuites(
            PreferredAEADCiphersuites.builder(false).apply {
                for (algorithm in aeadAlgorithms) {
                    addCombination(
                        algorithm.ciphermode.algorithmId, algorithm.aeadAlgorithm.algorithmId)
                }
            })

    override fun setPreferredAEADCiphersuites(
        algorithms: PreferredAEADCiphersuites.Builder?
    ): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS)
        algorithms?.let { subpacketsGenerator.setPreferredAEADCiphersuites(algorithms) }
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
        val clazz = if (isSensitive) 0x80.toByte() or 0x40.toByte() else 0x80.toByte()
        addRevocationKey(
            RevocationKey(isCritical, clazz, revocationKey.algorithm, revocationKey.fingerprint))
    }

    override fun addRevocationKey(revocationKey: RevocationKey): SignatureSubpackets = apply {
        subpacketsGenerator.addCustomSubpacket(revocationKey)
    }

    override fun clearRevocationKeys(): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.REVOCATION_KEY)
    }

    override fun setFeatures(vararg features: Feature): SignatureSubpackets = apply {
        setFeatures(true, *features)
    }

    override fun setFeatures(isCritical: Boolean, vararg features: Feature): SignatureSubpackets =
        apply {
            setFeatures(Features(isCritical, Feature.toBitmask(*features)))
        }

    override fun setFeatures(features: Features?): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.FEATURES)
        features?.let { subpacketsGenerator.setFeature(it.isCritical, it.features) }
    }

    override fun setAppropriateIssuerInfo(key: OpenPGPComponentKey): SignatureSubpackets = apply {
        setAppropriateIssuerInfo(key.pgpPublicKey)
    }

    override fun setAppropriateIssuerInfo(key: PGPPublicKey) = apply {
        setAppropriateIssuerInfo(key, OpenPGPKeyVersion.from(key.version))
    }

    override fun setAppropriateIssuerInfo(key: PGPPublicKey, version: OpenPGPKeyVersion) = apply {
        when (version) {
            OpenPGPKeyVersion.v3 -> setIssuerKeyId(key.keyID)
            OpenPGPKeyVersion.v4 -> setIssuerFingerprintAndKeyId(key)
            OpenPGPKeyVersion.librePgp,
            OpenPGPKeyVersion.v6 -> setIssuerFingerprint(key)
        }
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
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.ISSUER_KEY_ID)
        issuerKeyID?.let { subpacketsGenerator.setIssuerKeyID(it.isCritical, it.keyID) }
    }

    override fun setIssuerFingerprint(
        isCritical: Boolean,
        issuer: PGPPublicKey
    ): SignatureSubpackets = apply { subpacketsGenerator.setIssuerFingerprint(isCritical, issuer) }

    override fun setIssuerFingerprint(issuer: PGPPublicKey): SignatureSubpackets =
        setIssuerFingerprint(true, issuer)

    override fun setIssuerFingerprint(fingerprint: IssuerFingerprint?): SignatureSubpackets =
        apply {
            subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.ISSUER_FINGERPRINT)
            fingerprint?.let { subpacketsGenerator.addCustomSubpacket(it) }
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
    ): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.CREATION_TIME)
        creationTime?.let { subpacketsGenerator.setSignatureCreationTime(it.isCritical, it.time) }
    }

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
    ): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.EXPIRE_TIME)
        expirationTime?.let {
            subpacketsGenerator.setSignatureExpirationTime(it.isCritical, it.time)
        }
    }

    override fun setSignerUserId(userId: CharSequence): SignatureSubpackets = apply {
        setSignerUserId(false, userId)
    }

    override fun setSignerUserId(isCritical: Boolean, userId: CharSequence): SignatureSubpackets =
        apply {
            setSignerUserId(SignerUserID(isCritical, userId.toString()))
        }

    override fun setSignerUserId(signerUserID: SignerUserID?): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.SIGNER_USER_ID)
        signerUserID?.let { subpacketsGenerator.setSignerUserID(it.isCritical, it.rawID) }
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
        subpacketsGenerator.addNotationData(
            notationData.isCritical,
            notationData.isHumanReadable,
            notationData.notationName,
            notationData.notationValue)
    }

    override fun clearNotationData(): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.NOTATION_DATA)
    }

    override fun addIntendedRecipientFingerprint(recipientKey: PGPPublicKey): SignatureSubpackets =
        apply {
            addIntendedRecipientFingerprint(false, recipientKey)
        }

    override fun addIntendedRecipientFingerprint(
        isCritical: Boolean,
        recipientKey: PGPPublicKey
    ): SignatureSubpackets = apply {
        subpacketsGenerator.addIntendedRecipientFingerprint(isCritical, recipientKey)
    }

    override fun addIntendedRecipientFingerprint(
        intendedRecipient: IntendedRecipientFingerprint
    ): SignatureSubpackets = apply { subpacketsGenerator.addCustomSubpacket(intendedRecipient) }

    override fun clearIntendedRecipientFingerprints(): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(
            SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT)
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
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.EXPORTABLE)
        exportable?.let { subpacketsGenerator.setExportable(it.isCritical, it.isExportable) }
    }

    override fun setPolicyUrl(policyUrl: URL): SignatureSubpackets = apply {
        setPolicyUrl(false, policyUrl)
    }

    override fun setPolicyUrl(isCritical: Boolean, policyUrl: URL): SignatureSubpackets = apply {
        setPolicyUrl(PolicyURI(isCritical, policyUrl.toString()))
    }

    override fun setPolicyUrl(policyUrl: PolicyURI?): SignatureSubpackets = apply {
        policyUrl?.let { subpacketsGenerator.addPolicyURI(it.isCritical, it.uri) }
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
        regex?.let { subpacketsGenerator.addRegularExpression(it.isCritical, it.regex) }
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
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.REVOCABLE)
        revocable?.let { subpacketsGenerator.setRevocable(it.isCritical, it.isRevocable) }
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
            subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.SIGNATURE_TARGET)
            signatureTarget?.let {
                subpacketsGenerator.setSignatureTarget(
                    it.isCritical, it.publicKeyAlgorithm, it.hashAlgorithm, it.hashData)
            }
        }

    override fun setTrust(depth: Int, amount: Int): SignatureSubpackets = apply {
        setTrust(true, depth, amount)
    }

    override fun setTrust(isCritical: Boolean, depth: Int, amount: Int): SignatureSubpackets =
        apply {
            setTrust(TrustSignature(isCritical, depth, amount))
        }

    override fun setTrust(trust: TrustSignature?): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.TRUST_SIG)
        trust?.let { subpacketsGenerator.setTrust(it.isCritical, it.depth, it.trustAmount) }
    }

    override fun addEmbeddedSignature(signature: PGPSignature): SignatureSubpackets = apply {
        addEmbeddedSignature(true, signature)
    }

    override fun addEmbeddedSignature(
        isCritical: Boolean,
        signature: PGPSignature
    ): SignatureSubpackets = apply {
        subpacketsGenerator.addEmbeddedSignature(isCritical, signature)
    }

    override fun addEmbeddedSignature(embeddedSignature: EmbeddedSignature): SignatureSubpackets =
        apply {
            subpacketsGenerator.addCustomSubpacket(embeddedSignature)
        }

    override fun clearEmbeddedSignatures(): SignatureSubpackets = apply {
        subpacketsGenerator.removePacketsOfType(SignatureSubpacketTags.EMBEDDED_SIGNATURE)
    }

    fun addResidualSubpacket(
        subpacket: org.bouncycastle.bcpg.SignatureSubpacket
    ): SignatureSubpackets = apply { subpacketsGenerator.addCustomSubpacket(subpacket) }
}
