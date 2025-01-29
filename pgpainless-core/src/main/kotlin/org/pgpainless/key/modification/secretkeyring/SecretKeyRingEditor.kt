// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring

import java.util.*
import java.util.function.Predicate
import javax.annotation.Nonnull
import kotlin.NoSuchElementException
import openpgp.openPgpKeyId
import org.bouncycastle.bcpg.sig.KeyExpirationTime
import org.bouncycastle.openpgp.*
import org.pgpainless.PGPainless
import org.pgpainless.PGPainless.Companion.inspectKeyRing
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator
import org.pgpainless.bouncycastle.extensions.getKeyExpirationDate
import org.pgpainless.bouncycastle.extensions.publicKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.requirePublicKey
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.KeyRingBuilder
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.protection.*
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.key.util.KeyRingUtils.Companion.changePassphrase
import org.pgpainless.key.util.KeyRingUtils.Companion.injectCertification
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.signature.builder.*
import org.pgpainless.signature.subpackets.*
import org.pgpainless.util.Passphrase
import org.pgpainless.util.selection.userid.SelectUserId

class SecretKeyRingEditor(
    var secretKeyRing: PGPSecretKeyRing,
    override val referenceTime: Date = Date()
) : SecretKeyRingEditorInterface {

    override fun addUserId(
        userId: CharSequence,
        callback: SelfSignatureSubpackets.Callback?,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        val sanitizedUserId = sanitizeUserId(userId).toString()
        val primaryKey = secretKeyRing.secretKey

        val info = inspectKeyRing(secretKeyRing, referenceTime)
        require(!info.isHardRevoked(userId)) {
            "User-ID $userId is hard revoked and cannot be re-certified."
        }

        val (
            hashAlgorithmPreferences,
            symmetricKeyAlgorithmPreferences,
            compressionAlgorithmPreferences) =
            try {
                Triple(
                    info.preferredHashAlgorithms,
                    info.preferredSymmetricKeyAlgorithms,
                    info.preferredCompressionAlgorithms)
            } catch (e: IllegalStateException) { // missing user-id sig
                val algorithmSuite = AlgorithmSuite.defaultAlgorithmSuite
                Triple(
                    algorithmSuite.hashAlgorithms,
                    algorithmSuite.symmetricKeyAlgorithms,
                    algorithmSuite.compressionAlgorithms)
            }

        val builder =
            SelfSignatureBuilder(primaryKey, protector).apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                setSignatureType(SignatureType.POSITIVE_CERTIFICATION)
            }
        builder.hashedSubpackets.apply {
            setKeyFlags(info.getKeyFlagsOf(primaryKey.keyID))
            setPreferredHashAlgorithms(hashAlgorithmPreferences)
            setPreferredSymmetricKeyAlgorithms(symmetricKeyAlgorithmPreferences)
            setPreferredCompressionAlgorithms(compressionAlgorithmPreferences)
            setFeatures(Feature.MODIFICATION_DETECTION)
        }
        builder.applyCallback(callback)
        secretKeyRing =
            injectCertification(secretKeyRing, sanitizedUserId, builder.build(sanitizedUserId))
        return this
    }

    override fun addPrimaryUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        val uid = sanitizeUserId(userId)
        val primaryKey = secretKeyRing.publicKey
        var info = inspectKeyRing(secretKeyRing, referenceTime)
        val primaryUserId = info.primaryUserId
        val signature =
            if (primaryUserId == null) info.latestDirectKeySelfSignature
            else info.getLatestUserIdCertification(primaryUserId)
        val previousKeyExpiration = signature?.getKeyExpirationDate(primaryKey.creationTime)

        // Add new primary user-id signature
        addUserId(
            uid,
            object : SelfSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    hashedSubpackets.apply {
                        setPrimaryUserId()
                        if (previousKeyExpiration != null)
                            setKeyExpirationTime(primaryKey, previousKeyExpiration)
                        else setKeyExpirationTime(null)
                    }
                }
            },
            protector)

        // unmark previous primary user-ids to be non-primary
        info = inspectKeyRing(secretKeyRing, referenceTime)
        info.validAndExpiredUserIds
            .filterNot { it == uid }
            .forEach { otherUserId ->
                if (info
                    .getLatestUserIdCertification(otherUserId)!!
                    .hashedSubPackets
                    .isPrimaryUserID) {
                    // We need to unmark this user-id as primary
                    addUserId(
                        otherUserId,
                        object : SelfSignatureSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: SelfSignatureSubpackets
                            ) {
                                hashedSubpackets.apply {
                                    setPrimaryUserId(null)
                                    setKeyExpirationTime(null) // non-primary
                                }
                            }
                        },
                        protector)
                }
            }
        return this
    }

    @Deprecated(
        "Use of SelectUserId class is deprecated.",
        replaceWith = ReplaceWith("removeUserId(protector, predicate)"))
    override fun removeUserId(
        selector: SelectUserId,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        return revokeUserIds(
            selector,
            protector,
            RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                .withoutDescription())
    }

    override fun removeUserId(
        protector: SecretKeyRingProtector,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface {
        return revokeUserIds(
            protector,
            RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                .withoutDescription(),
            predicate)
    }

    override fun removeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        return removeUserId(protector) { uid -> userId == uid }
    }

    override fun replaceUserId(
        oldUserId: CharSequence,
        newUserId: CharSequence,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        val oldUID = sanitizeUserId(oldUserId)
        val newUID = sanitizeUserId(newUserId)
        require(oldUID.isNotBlank()) { "Old user-ID cannot be empty." }
        require(newUID.isNotBlank()) { "New user-ID cannot be empty." }

        val info = inspectKeyRing(secretKeyRing, referenceTime)
        if (!info.isUserIdValid(oldUID)) {
            throw NoSuchElementException(
                "Key does not carry user-ID '$oldUID', or it is not valid.")
        }

        val oldCertification =
            info.getLatestUserIdCertification(oldUID)
                ?: throw AssertionError("Certification for old user-ID MUST NOT be null.")

        addUserId(
            newUID,
            object : SelfSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    SignatureSubpacketsHelper.applyFrom(
                        oldCertification.hashedSubPackets, hashedSubpackets as SignatureSubpackets)
                    if (oldUID == info.primaryUserId &&
                        !oldCertification.hashedSubPackets.isPrimaryUserID) {
                        hashedSubpackets.setPrimaryUserId()
                    }
                }

                override fun modifyUnhashedSubpackets(unhashedSubpackets: SelfSignatureSubpackets) {
                    SignatureSubpacketsHelper.applyFrom(
                        oldCertification.unhashedSubPackets,
                        unhashedSubpackets as SignatureSubpackets)
                }
            },
            protector)

        return revokeUserId(oldUID, protector)
    }

    override fun addSubKey(
        keySpec: KeySpec,
        subkeyPassphrase: Passphrase,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        val callback =
            object : SelfSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    SignatureSubpacketsHelper.applyFrom(
                        keySpec.subpackets, hashedSubpackets as SignatureSubpackets)
                    hashedSubpackets.setSignatureCreationTime(referenceTime)
                }
            }
        return addSubKey(keySpec, subkeyPassphrase, callback, protector)
    }

    override fun addSubKey(
        keySpec: KeySpec,
        subkeyPassphrase: Passphrase,
        callback: SelfSignatureSubpackets.Callback?,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        val version = OpenPGPKeyVersion.from(secretKeyRing.getPublicKey().version)
        val keyPair = KeyRingBuilder.generateKeyPair(keySpec, OpenPGPKeyVersion.v4, referenceTime)
        val subkeyProtector =
            PasswordBasedSecretKeyRingProtector.forKeyId(keyPair.keyID, subkeyPassphrase)
        val keyFlags = KeyFlag.fromBitmask(keySpec.subpackets.keyFlags).toMutableList()
        return addSubKey(
            keyPair,
            callback,
            subkeyProtector,
            protector,
            keyFlags.removeFirst(),
            *keyFlags.toTypedArray())
    }

    override fun addSubKey(
        subkey: PGPKeyPair,
        callback: SelfSignatureSubpackets.Callback?,
        subkeyProtector: SecretKeyRingProtector,
        primaryKeyProtector: SecretKeyRingProtector,
        keyFlag: KeyFlag,
        vararg keyFlags: KeyFlag
    ): SecretKeyRingEditorInterface {
        val flags = listOf(keyFlag).plus(keyFlags)
        val subkeyAlgorithm = subkey.publicKey.publicKeyAlgorithm
        SignatureSubpacketsUtil.assureKeyCanCarryFlags(subkeyAlgorithm)

        val bitStrength = subkey.publicKey.bitStrength
        require(
            PGPainless.getPolicy()
                .publicKeyAlgorithmPolicy
                .isAcceptable(subkeyAlgorithm, bitStrength)) {
                "Public key algorithm policy violation: $subkeyAlgorithm with bit strength $bitStrength is not acceptable."
            }

        val primaryKey = secretKeyRing.secretKey
        val info = inspectKeyRing(secretKeyRing, referenceTime)
        val hashAlgorithm =
            HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(PGPainless.getPolicy())
                .negotiateHashAlgorithm(info.preferredHashAlgorithms)

        var secretSubkey =
            PGPSecretKey(
                subkey.privateKey,
                subkey.publicKey,
                ImplementationFactory.getInstance().v4FingerprintCalculator,
                false,
                subkeyProtector.getEncryptor(subkey.keyID))
        val skBindingBuilder =
            SubkeyBindingSignatureBuilder(primaryKey, primaryKeyProtector, hashAlgorithm)
        skBindingBuilder.apply {
            hashedSubpackets.setSignatureCreationTime(referenceTime)
            hashedSubpackets.setKeyFlags(flags)
            if (subkeyAlgorithm.isSigningCapable()) {
                val pkBindingBuilder =
                    PrimaryKeyBindingSignatureBuilder(secretSubkey, subkeyProtector, hashAlgorithm)
                pkBindingBuilder.hashedSubpackets.setSignatureCreationTime(referenceTime)
                hashedSubpackets.addEmbeddedSignature(pkBindingBuilder.build(primaryKey.publicKey))
            }
            applyCallback(callback)
        }
        secretSubkey =
            KeyRingUtils.secretKeyPlusSignature(
                secretSubkey, skBindingBuilder.build(secretSubkey.publicKey))
        secretKeyRing = KeyRingUtils.keysPlusSecretKey(secretKeyRing, secretSubkey)
        return this
    }

    override fun revoke(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): SecretKeyRingEditorInterface {
        return revoke(protector, callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun revoke(
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        return revokeSubKey(secretKeyRing.secretKey.keyID, protector, callback)
    }

    override fun revokeSubKey(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): SecretKeyRingEditorInterface {
        return revokeSubKey(
            subkeyId, protector, callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun revokeSubKey(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        val revokeeSubKey = secretKeyRing.requirePublicKey(subkeyId)
        val subkeyRevocation = generateRevocation(protector, revokeeSubKey, callback)
        secretKeyRing = injectCertification(secretKeyRing, revokeeSubKey, subkeyRevocation)
        return this
    }

    override fun revokeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): SecretKeyRingEditorInterface {
        if (revocationAttributes != null) {
            require(
                revocationAttributes.reason == RevocationAttributes.Reason.NO_REASON ||
                    revocationAttributes.reason ==
                        RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID) {
                    "Revocation reason must either be NO_REASON or USER_ID_NO_LONGER_VALID"
                }
        }

        return revokeUserId(
            userId,
            protector,
            object : RevocationSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(
                    hashedSubpackets: RevocationSignatureSubpackets
                ) {
                    if (revocationAttributes != null) {
                        hashedSubpackets.setRevocationReason(false, revocationAttributes)
                    }
                }
            })
    }

    override fun revokeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        return revokeUserIds(protector, callback, SelectUserId.exactMatch(sanitizeUserId(userId)))
    }

    override fun revokeUserIds(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface {
        return revokeUserIds(
            protector,
            object : RevocationSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(
                    hashedSubpackets: RevocationSignatureSubpackets
                ) {
                    if (revocationAttributes != null)
                        hashedSubpackets.setRevocationReason(revocationAttributes)
                }
            },
            predicate)
    }

    override fun revokeUserIds(
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface {
        selectUserIds(predicate)
            .also {
                if (it.isEmpty())
                    throw NoSuchElementException("No matching user-ids found on the key.")
            }
            .forEach { userId -> doRevokeUserId(userId, protector, callback) }
        return this
    }

    override fun setExpirationDate(
        expiration: Date?,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        require(secretKeyRing.secretKey.isMasterKey) {
            "OpenPGP key does not appear to contain a primary secret key."
        }

        val prevDirectKeySig = getPreviousDirectKeySignature()
        // reissue direct key sig
        if (prevDirectKeySig != null) {
            secretKeyRing =
                injectCertification(
                    secretKeyRing,
                    secretKeyRing.publicKey,
                    reissueDirectKeySignature(expiration, protector, prevDirectKeySig))
        }

        val primaryUserId =
            inspectKeyRing(secretKeyRing, referenceTime).getPossiblyExpiredPrimaryUserId()
        if (primaryUserId != null) {
            val prevUserIdSig = getPreviousUserIdSignatures(primaryUserId)
            val userIdSig =
                reissuePrimaryUserIdSig(expiration, protector, primaryUserId, prevUserIdSig!!)
            secretKeyRing = injectCertification(secretKeyRing, primaryUserId, userIdSig)
        }

        val info = inspectKeyRing(secretKeyRing, referenceTime)
        for (userId in info.validUserIds) {
            if (userId == primaryUserId) {
                continue
            }

            val prevUserIdSig =
                info.getLatestUserIdCertification(userId)
                    ?: throw AssertionError(
                        "A valid user-id shall never have no user-id signature.")
            if (prevUserIdSig.hashedSubPackets.isPrimaryUserID) {
                secretKeyRing =
                    injectCertification(
                        secretKeyRing,
                        primaryUserId!!,
                        reissueNonPrimaryUserId(protector, userId, prevUserIdSig))
            }
        }

        return this
    }

    override fun setExpirationDateOfSubkey(
        expiration: Date?,
        keyId: Long,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface = apply {
        // is primary key
        if (keyId == secretKeyRing.publicKey.keyID) {
            return setExpirationDate(expiration, protector)
        }

        // is subkey
        val subkey =
            secretKeyRing.getPublicKey(keyId)
                ?: throw NoSuchElementException("No subkey with ID ${keyId.openPgpKeyId()} found.")
        val prevBinding =
            inspectKeyRing(secretKeyRing).getCurrentSubkeyBindingSignature(keyId)
                ?: throw NoSuchElementException(
                    "Previous subkey binding signature for ${keyId.openPgpKeyId()} MUST NOT be null.")
        val bindingSig = reissueSubkeyBindingSignature(subkey, expiration, protector, prevBinding)
        secretKeyRing = injectCertification(secretKeyRing, subkey, bindingSig)
    }

    override fun createMinimalRevocationCertificate(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPPublicKeyRing {
        // Check reason
        if (revocationAttributes != null) {
            require(RevocationAttributes.Reason.isKeyRevocation(revocationAttributes.reason)) {
                "Revocation reason MUST be applicable to a key revocation."
            }
        }

        val revocation = createRevocation(protector, revocationAttributes)
        var primaryKey = secretKeyRing.secretKey.publicKey
        primaryKey = KeyRingUtils.getStrippedDownPublicKey(primaryKey)
        primaryKey = PGPPublicKey.addCertification(primaryKey, revocation)
        return PGPPublicKeyRing(listOf(primaryKey))
    }

    override fun createRevocation(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPSignature {
        return generateRevocation(
            protector,
            secretKeyRing.publicKey,
            callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun createRevocation(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPSignature {
        return generateRevocation(
            protector,
            secretKeyRing.requirePublicKey(subkeyId),
            callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun createRevocation(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): PGPSignature {
        return generateRevocation(protector, secretKeyRing.requirePublicKey(subkeyId), callback)
    }

    override fun createRevocation(
        subkeyFingerprint: OpenPgpFingerprint,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPSignature {
        return generateRevocation(
            protector,
            secretKeyRing.requirePublicKey(subkeyFingerprint),
            callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun changePassphraseFromOldPassphrase(
        oldPassphrase: Passphrase,
        oldProtectionSettings: KeyRingProtectionSettings
    ): SecretKeyRingEditorInterface.WithKeyRingEncryptionSettings {
        return WithKeyRingEncryptionSettingsImpl(
            this,
            null,
            PasswordBasedSecretKeyRingProtector(
                oldProtectionSettings, SolitaryPassphraseProvider(oldPassphrase)))
    }

    override fun changeSubKeyPassphraseFromOldPassphrase(
        keyId: Long,
        oldPassphrase: Passphrase,
        oldProtectionSettings: KeyRingProtectionSettings
    ): SecretKeyRingEditorInterface.WithKeyRingEncryptionSettings {
        return WithKeyRingEncryptionSettingsImpl(
            this,
            keyId,
            CachingSecretKeyRingProtector(
                mapOf(keyId to oldPassphrase), oldProtectionSettings, null))
    }

    override fun done(): PGPSecretKeyRing {
        return secretKeyRing
    }

    private fun sanitizeUserId(userId: CharSequence): CharSequence =
        // I'm not sure, what kind of sanitization is needed.
        // Newlines are allowed, they just need to be escaped when emitted in an ASCII armor header
        // Trailing/Leading whitespace is also fine.
        userId.toString()

    private fun callbackFromRevocationAttributes(attributes: RevocationAttributes?) =
        object : RevocationSignatureSubpackets.Callback {
            override fun modifyHashedSubpackets(hashedSubpackets: RevocationSignatureSubpackets) {
                if (attributes != null) {
                    hashedSubpackets.setRevocationReason(attributes)
                }
            }
        }

    private fun generateRevocation(
        protector: SecretKeyRingProtector,
        revokeeSubkey: PGPPublicKey,
        callback: RevocationSignatureSubpackets.Callback?
    ): PGPSignature {
        val primaryKey = secretKeyRing.secretKey
        val signatureType =
            if (revokeeSubkey.isMasterKey) SignatureType.KEY_REVOCATION
            else SignatureType.SUBKEY_REVOCATION

        return RevocationSignatureBuilder(signatureType, primaryKey, protector)
            .apply { applyCallback(callback) }
            .build(revokeeSubkey)
    }

    private fun doRevokeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        RevocationSignatureBuilder(
                SignatureType.CERTIFICATION_REVOCATION, secretKeyRing.secretKey, protector)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(callback)
            }
            .let {
                secretKeyRing =
                    injectCertification(secretKeyRing, userId, it.build(userId.toString()))
            }
        return this
    }

    private fun getPreviousDirectKeySignature(): PGPSignature? {
        val info = inspectKeyRing(secretKeyRing, referenceTime)
        return info.latestDirectKeySelfSignature
    }

    private fun getPreviousUserIdSignatures(userId: String): PGPSignature? {
        val info = inspectKeyRing(secretKeyRing, referenceTime)
        return info.getLatestUserIdCertification(userId)
    }

    @Throws(PGPException::class)
    private fun reissueNonPrimaryUserId(
        secretKeyRingProtector: SecretKeyRingProtector,
        userId: String,
        prevUserIdSig: PGPSignature
    ): PGPSignature {
        val builder =
            SelfSignatureBuilder(secretKeyRing.secretKey, secretKeyRingProtector, prevUserIdSig)
        builder.hashedSubpackets.setSignatureCreationTime(referenceTime)
        builder.applyCallback(
            object : SelfSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    // unmark as primary
                    hashedSubpackets.setPrimaryUserId(null)
                }
            })
        return builder.build(userId)
    }

    @Throws(PGPException::class)
    private fun reissuePrimaryUserIdSig(
        expiration: Date?,
        @Nonnull secretKeyRingProtector: SecretKeyRingProtector,
        @Nonnull primaryUserId: String,
        @Nonnull prevUserIdSig: PGPSignature
    ): PGPSignature {
        return SelfSignatureBuilder(secretKeyRing.secretKey, secretKeyRingProtector, prevUserIdSig)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(
                    object : SelfSignatureSubpackets.Callback {
                        override fun modifyHashedSubpackets(
                            hashedSubpackets: SelfSignatureSubpackets
                        ) {
                            if (expiration != null) {
                                hashedSubpackets.setKeyExpirationTime(
                                    true, secretKeyRing.publicKey.creationTime, expiration)
                            } else {
                                hashedSubpackets.setKeyExpirationTime(KeyExpirationTime(true, 0))
                            }
                            hashedSubpackets.setPrimaryUserId()
                        }
                    })
            }
            .build(primaryUserId)
    }

    @Throws(PGPException::class)
    private fun reissueDirectKeySignature(
        expiration: Date?,
        secretKeyRingProtector: SecretKeyRingProtector,
        prevDirectKeySig: PGPSignature
    ): PGPSignature {
        return DirectKeySelfSignatureBuilder(
                secretKeyRing.secretKey, secretKeyRingProtector, prevDirectKeySig)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(
                    object : SelfSignatureSubpackets.Callback {
                        override fun modifyHashedSubpackets(
                            hashedSubpackets: SelfSignatureSubpackets
                        ) {
                            if (expiration != null) {
                                hashedSubpackets.setKeyExpirationTime(
                                    secretKeyRing.publicKey.creationTime, expiration)
                            } else {
                                hashedSubpackets.setKeyExpirationTime(null)
                            }
                        }
                    })
            }
            .build()
    }

    private fun reissueSubkeyBindingSignature(
        subkey: PGPPublicKey,
        expiration: Date?,
        protector: SecretKeyRingProtector,
        prevSubkeyBindingSignature: PGPSignature
    ): PGPSignature {
        val primaryKey = secretKeyRing.publicKey
        val secretPrimaryKey = secretKeyRing.secretKey
        val secretSubkey: PGPSecretKey? = secretKeyRing.getSecretKey(subkey.keyID)

        val builder =
            SubkeyBindingSignatureBuilder(secretPrimaryKey, protector, prevSubkeyBindingSignature)
        builder.hashedSubpackets.apply {
            // set expiration
            setSignatureCreationTime(referenceTime)
            setKeyExpirationTime(subkey, expiration)
            setSignatureExpirationTime(null) // avoid copying sig exp time

            // signing-capable subkeys need embedded primary key binding sig
            SignatureSubpacketsUtil.parseKeyFlags(prevSubkeyBindingSignature)?.let { flags ->
                if (flags.contains(KeyFlag.SIGN_DATA)) {
                    if (secretSubkey == null) {
                        throw NoSuchElementException(
                            "Secret key does not contain secret-key" +
                                " component for subkey ${subkey.keyID.openPgpKeyId()}")
                    }

                    // create new embedded back-sig
                    clearEmbeddedSignatures()
                    addEmbeddedSignature(
                        PrimaryKeyBindingSignatureBuilder(secretSubkey, protector)
                            .build(primaryKey))
                }
            }
        }

        return builder.build(subkey)
    }

    private fun selectUserIds(predicate: Predicate<String>): List<String> =
        inspectKeyRing(secretKeyRing).validUserIds.filter { predicate.test(it) }

    private class WithKeyRingEncryptionSettingsImpl(
        private val editor: SecretKeyRingEditor,
        private val keyId: Long?,
        private val oldProtector: SecretKeyRingProtector
    ) : SecretKeyRingEditorInterface.WithKeyRingEncryptionSettings {

        override fun withSecureDefaultSettings(): SecretKeyRingEditorInterface.WithPassphrase {
            return withCustomSettings(KeyRingProtectionSettings.secureDefaultSettings())
        }

        override fun withCustomSettings(
            settings: KeyRingProtectionSettings
        ): SecretKeyRingEditorInterface.WithPassphrase {
            return WithPassphraseImpl(editor, keyId, oldProtector, settings)
        }
    }

    private class WithPassphraseImpl(
        private val editor: SecretKeyRingEditor,
        private val keyId: Long?,
        private val oldProtector: SecretKeyRingProtector,
        private val newProtectionSettings: KeyRingProtectionSettings
    ) : SecretKeyRingEditorInterface.WithPassphrase {

        override fun toNewPassphrase(passphrase: Passphrase): SecretKeyRingEditorInterface {
            val protector =
                PasswordBasedSecretKeyRingProtector(
                    newProtectionSettings, SolitaryPassphraseProvider(passphrase))
            val secretKeys = changePassphrase(keyId, editor.secretKeyRing, oldProtector, protector)
            editor.secretKeyRing = secretKeys
            return editor
        }

        override fun toNoPassphrase(): SecretKeyRingEditorInterface {
            val protector = UnprotectedKeysProtector()
            val secretKeys = changePassphrase(keyId, editor.secretKeyRing, oldProtector, protector)
            editor.secretKeyRing = secretKeys
            return editor
        }
    }
}
