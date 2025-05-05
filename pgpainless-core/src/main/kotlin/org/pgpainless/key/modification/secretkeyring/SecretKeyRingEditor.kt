// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring

import java.util.*
import java.util.function.Predicate
import javax.annotation.Nonnull
import kotlin.NoSuchElementException
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.bcpg.sig.KeyExpirationTime
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPSubkey
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey
import org.bouncycastle.openpgp.api.OpenPGPKeyEditor
import org.bouncycastle.openpgp.api.OpenPGPSignature
import org.bouncycastle.openpgp.api.SignatureParameters
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator
import org.pgpainless.bouncycastle.extensions.checksumCalculator
import org.pgpainless.bouncycastle.extensions.getKeyExpirationDate
import org.pgpainless.bouncycastle.extensions.publicKeyAlgorithm
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
    var key: OpenPGPKey,
    val api: PGPainless = PGPainless.getInstance(),
    override val referenceTime: Date = Date()
) : SecretKeyRingEditorInterface {

    @JvmOverloads
    constructor(
        secretKeyRing: PGPSecretKeyRing,
        api: PGPainless = PGPainless.getInstance(),
        referenceTime: Date = Date()
    ) : this(PGPainless.getInstance().toKey(secretKeyRing), api, referenceTime)

    override fun addUserId(
        userId: CharSequence,
        callback: SelfSignatureSubpackets.Callback?,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        val info = api.inspect(key, referenceTime)
        require(!info.isHardRevoked(userId)) {
            "User-ID $userId is hard revoked and cannot be re-certified."
        }

        val hashAlgorithmPreferences =
            info.preferredHashAlgorithms ?: AlgorithmSuite.defaultHashAlgorithms
        val symmetricAlgorithmPreferences =
            info.preferredSymmetricKeyAlgorithms ?: AlgorithmSuite.defaultSymmetricKeyAlgorithms
        val compressionAlgorithmPreferences =
            info.preferredCompressionAlgorithms ?: AlgorithmSuite.defaultCompressionAlgorithms
        val aeadAlgorithmPreferences =
            info.preferredAEADCipherSuites ?: AlgorithmSuite.defaultAEADAlgorithmSuites

        key =
            OpenPGPKeyEditor(key, protector)
                .addUserId(
                    sanitizeUserId(userId).toString(),
                    object : SignatureParameters.Callback {
                        override fun apply(parameters: SignatureParameters): SignatureParameters {
                            return parameters
                                .setSignatureCreationTime(referenceTime)
                                .setHashedSubpacketsFunction { subpacketGenerator ->
                                    val subpackets = SignatureSubpackets(subpacketGenerator)
                                    subpackets.setAppropriateIssuerInfo(key.primaryKey.pgpPublicKey)

                                    subpackets.setKeyFlags(info.getKeyFlagsOf(key.keyIdentifier))
                                    subpackets.setPreferredHashAlgorithms(hashAlgorithmPreferences)
                                    subpackets.setPreferredSymmetricKeyAlgorithms(
                                        symmetricAlgorithmPreferences)
                                    subpackets.setPreferredCompressionAlgorithms(
                                        compressionAlgorithmPreferences)
                                    subpackets.setPreferredAEADCiphersuites(
                                        aeadAlgorithmPreferences)

                                    callback?.modifyHashedSubpackets(subpackets)
                                    subpacketGenerator
                                }
                                .setUnhashedSubpacketsFunction { subpacketGenerator ->
                                    callback?.modifyUnhashedSubpackets(
                                        SignatureSubpackets(subpacketGenerator))
                                    subpacketGenerator
                                }
                        }
                    })
                .done()
        return this
    }

    override fun addPrimaryUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface {
        val uid = sanitizeUserId(userId)
        val primaryKey = key.primaryKey.pgpPublicKey
        var info = api.inspect(key, referenceTime)
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
        info = api.inspect(key, referenceTime)
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

        val info = api.inspect(key, referenceTime)
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
                    hashedSubpackets.apply {
                        setKeyFlags(keySpec.keyFlags)
                        keySpec.preferredHashAlgorithmsOverride?.let {
                            setPreferredHashAlgorithms(it)
                        }
                        keySpec.preferredCompressionAlgorithmsOverride?.let {
                            setPreferredCompressionAlgorithms(it)
                        }
                        keySpec.preferredSymmetricAlgorithmsOverride?.let {
                            setPreferredSymmetricKeyAlgorithms(it)
                        }
                        keySpec.preferredAEADAlgorithmsOverride?.let {
                            setPreferredAEADCiphersuites(it)
                        }
                        keySpec.featuresOverride?.let { setFeatures(*it.toTypedArray()) }
                    }
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
        val version = OpenPGPKeyVersion.from(key.primarySecretKey.version)
        val keyPair = KeyRingBuilder.generateKeyPair(keySpec, version, api.implementation)
        val subkeyProtector =
            PasswordBasedSecretKeyRingProtector.forKeyId(keyPair.keyIdentifier, subkeyPassphrase)
        val keyFlags = keySpec.keyFlags.toMutableList()
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
            api.algorithmPolicy.publicKeyAlgorithmPolicy.isAcceptable(
                subkeyAlgorithm, bitStrength)) {
                "Public key algorithm policy violation: $subkeyAlgorithm with bit strength $bitStrength is not acceptable."
            }

        val primaryKey = key.primarySecretKey.pgpSecretKey
        val info = api.inspect(key, referenceTime)
        val hashAlgorithm =
            HashAlgorithmNegotiator.negotiateSignatureHashAlgorithm(api.algorithmPolicy)
                .negotiateHashAlgorithm(info.preferredHashAlgorithms)

        var secretSubkey =
            PGPSecretKey(
                subkey.privateKey,
                subkey.publicKey,
                OpenPGPImplementation.getInstance().checksumCalculator(),
                false,
                subkeyProtector.getEncryptor(subkey.publicKey))

        val componentKey =
            OpenPGPSecretKey(
                OpenPGPSubkey(subkey.publicKey, key),
                secretSubkey,
                PGPainless.getInstance().implementation.pbeSecretKeyDecryptorBuilderProvider())

        val skBindingBuilder =
            SubkeyBindingSignatureBuilder(
                key.primarySecretKey, primaryKeyProtector, hashAlgorithm, api)
        skBindingBuilder.apply {
            hashedSubpackets.setSignatureCreationTime(referenceTime)
            hashedSubpackets.setKeyFlags(flags)
            if (subkeyAlgorithm.isSigningCapable()) {
                val pkBindingBuilder =
                    PrimaryKeyBindingSignatureBuilder(
                        componentKey, subkeyProtector, hashAlgorithm, api)
                pkBindingBuilder.hashedSubpackets.setSignatureCreationTime(referenceTime)
                hashedSubpackets.addEmbeddedSignature(pkBindingBuilder.build(primaryKey.publicKey))
            }
            applyCallback(callback)
        }
        secretSubkey =
            KeyRingUtils.secretKeyPlusSignature(
                secretSubkey, skBindingBuilder.build(secretSubkey.publicKey))
        val secretKeyRing = KeyRingUtils.keysPlusSecretKey(key.pgpSecretKeyRing, secretSubkey)
        key = api.toKey(secretKeyRing)
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
        return revokeSubKey(key.keyIdentifier, protector, callback)
    }

    override fun revokeSubKey(
        subkeyIdentifier: KeyIdentifier,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): SecretKeyRingEditorInterface {
        return revokeSubKey(
            subkeyIdentifier, protector, callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun revokeSubKey(
        subkeyIdentifier: KeyIdentifier,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        var secretKeyRing = key.pgpSecretKeyRing
        val revokeeSubKey =
            key.getKey(subkeyIdentifier)
                ?: throw NoSuchElementException(
                    "Certificate ${key.keyIdentifier} does not contain subkey $subkeyIdentifier")
        val subkeyRevocation = generateRevocation(protector, revokeeSubKey, callback)
        secretKeyRing =
            injectCertification(
                secretKeyRing, revokeeSubKey.pgpPublicKey, subkeyRevocation.signature)
        key = api.toKey(secretKeyRing)
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
        var secretKeyRing = key.pgpSecretKeyRing
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
                    reissueDirectKeySignature(expiration, protector, prevDirectKeySig).signature)
        }

        val info = api.inspect(key, referenceTime)

        val primaryUserId = info.getPossiblyExpiredPrimaryUserId()
        if (primaryUserId != null) {
            val prevUserIdSig = getPreviousUserIdSignatures(primaryUserId)
            val userIdSig =
                reissuePrimaryUserIdSig(expiration, protector, primaryUserId, prevUserIdSig!!)
            secretKeyRing = injectCertification(secretKeyRing, primaryUserId, userIdSig)
        }

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

        key = api.toKey(secretKeyRing)
        return this
    }

    override fun setExpirationDateOfSubkey(
        expiration: Date?,
        keyId: KeyIdentifier,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface = apply {
        var secretKeyRing = key.pgpSecretKeyRing

        // is primary key
        if (keyId.matches(key.keyIdentifier)) {
            return setExpirationDate(expiration, protector)
        }

        // is subkey
        val subkey =
            key.getKey(keyId) ?: throw NoSuchElementException("No subkey with ID $keyId found.")
        val prevBinding =
            api.inspect(key).getCurrentSubkeyBindingSignature(keyId)
                ?: throw NoSuchElementException(
                    "Previous subkey binding signaure for $keyId MUST NOT be null.")
        val bindingSig = reissueSubkeyBindingSignature(subkey, expiration, protector, prevBinding)
        secretKeyRing =
            injectCertification(secretKeyRing, subkey.pgpPublicKey, bindingSig.signature)

        key = api.toKey(secretKeyRing)
    }

    override fun createMinimalRevocationCertificate(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): OpenPGPCertificate {
        // Check reason
        if (revocationAttributes != null) {
            require(RevocationAttributes.Reason.isKeyRevocation(revocationAttributes.reason)) {
                "Revocation reason MUST be applicable to a key revocation."
            }
        }

        val revocation = createRevocation(protector, revocationAttributes)
        var primaryKey = key.primaryKey.pgpPublicKey
        primaryKey = KeyRingUtils.getStrippedDownPublicKey(primaryKey)
        primaryKey = PGPPublicKey.addCertification(primaryKey, revocation.signature)
        return api.toCertificate(PGPPublicKeyRing(listOf(primaryKey)))
    }

    override fun createRevocation(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): OpenPGPSignature {
        return generateRevocation(
            protector, key.primaryKey, callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun createRevocation(
        subkeyIdentifier: KeyIdentifier,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): OpenPGPSignature {
        return generateRevocation(
            protector,
            key.getKey(subkeyIdentifier),
            callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun createRevocation(
        subkeyIdentifier: KeyIdentifier,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): OpenPGPSignature {
        return generateRevocation(protector, key.getKey(subkeyIdentifier), callback)
    }

    override fun createRevocation(
        subkeyFingerprint: OpenPgpFingerprint,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): OpenPGPSignature {
        return generateRevocation(
            protector,
            key.getKey(subkeyFingerprint.keyIdentifier),
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
        keyIdentifier: KeyIdentifier,
        oldPassphrase: Passphrase,
        oldProtectionSettings: KeyRingProtectionSettings
    ): SecretKeyRingEditorInterface.WithKeyRingEncryptionSettings {
        return WithKeyRingEncryptionSettingsImpl(
            this,
            keyIdentifier,
            CachingSecretKeyRingProtector(
                mapOf(keyIdentifier to oldPassphrase), oldProtectionSettings, null))
    }

    override fun done(): OpenPGPKey {
        return key
    }

    private fun sanitizeUserId(userId: CharSequence): CharSequence =
        // TODO: Further research how to sanitize user IDs.
        //  e.g. what about newlines?
        userId.toString().trim()

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
        revokeeSubkey: OpenPGPComponentKey,
        callback: RevocationSignatureSubpackets.Callback?
    ): OpenPGPSignature {
        val signatureType =
            if (revokeeSubkey.isPrimaryKey) SignatureType.KEY_REVOCATION
            else SignatureType.SUBKEY_REVOCATION

        return RevocationSignatureBuilder(signatureType, key.primarySecretKey, protector, api)
            .apply { applyCallback(callback) }
            .build(revokeeSubkey)
    }

    private fun doRevokeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        RevocationSignatureBuilder(
                SignatureType.CERTIFICATION_REVOCATION, key.primarySecretKey, protector, api)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(callback)
            }
            .let {
                val secretKeyRing =
                    injectCertification(key.pgpSecretKeyRing, userId, it.build(userId.toString()))
                key = api.toKey(secretKeyRing)
            }
        return this
    }

    private fun getPreviousDirectKeySignature(): PGPSignature? {
        val info = api.inspect(key, referenceTime)
        return info.latestDirectKeySelfSignature
    }

    private fun getPreviousUserIdSignatures(userId: String): PGPSignature? {
        val info = api.inspect(key, referenceTime)
        return info.getLatestUserIdCertification(userId)
    }

    @Throws(PGPException::class)
    private fun reissueNonPrimaryUserId(
        secretKeyRingProtector: SecretKeyRingProtector,
        userId: String,
        prevUserIdSig: PGPSignature
    ): PGPSignature {
        val builder =
            SelfSignatureBuilder(key.primarySecretKey, secretKeyRingProtector, prevUserIdSig, api)
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
        return SelfSignatureBuilder(
                key.primarySecretKey, secretKeyRingProtector, prevUserIdSig, api)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(
                    object : SelfSignatureSubpackets.Callback {
                        override fun modifyHashedSubpackets(
                            hashedSubpackets: SelfSignatureSubpackets
                        ) {
                            if (expiration != null) {
                                hashedSubpackets.setKeyExpirationTime(
                                    true, key.primaryKey.creationTime, expiration)
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
    ): OpenPGPSignature {
        val secretKeyRing = key.pgpSecretKeyRing
        return DirectKeySelfSignatureBuilder(
                secretKeyRing, secretKeyRingProtector, prevDirectKeySig, api)
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
        subkey: OpenPGPComponentKey,
        expiration: Date?,
        protector: SecretKeyRingProtector,
        prevSubkeyBindingSignature: PGPSignature
    ): OpenPGPSignature {
        val primaryKey = key.primaryKey
        val secretSubkey: OpenPGPSecretKey? = key.getSecretKey(subkey)

        val builder =
            SubkeyBindingSignatureBuilder(
                key.primarySecretKey, protector, prevSubkeyBindingSignature, api)
        builder.hashedSubpackets.apply {
            // set expiration
            setSignatureCreationTime(referenceTime)
            setKeyExpirationTime(subkey.pgpPublicKey, expiration)
            setSignatureExpirationTime(null) // avoid copying sig exp time

            // signing-capable subkeys need embedded primary key binding sig
            SignatureSubpacketsUtil.parseKeyFlags(prevSubkeyBindingSignature)?.let { flags ->
                if (flags.contains(KeyFlag.SIGN_DATA)) {
                    if (secretSubkey == null) {
                        throw NoSuchElementException(
                            "Secret key does not contain secret-key" +
                                " component for subkey ${subkey.keyIdentifier}")
                    }

                    // create new embedded back-sig
                    clearEmbeddedSignatures()
                    addEmbeddedSignature(
                        PrimaryKeyBindingSignatureBuilder(
                                key.getSecretKey(subkey.keyIdentifier), protector, api)
                            .build(primaryKey)
                            .signature)
                }
            }
        }

        return builder.build(subkey)
    }

    private fun selectUserIds(predicate: Predicate<String>): List<String> =
        key.validUserIds.map { it.userId }.filter { predicate.test(it) }.toList()

    private class WithKeyRingEncryptionSettingsImpl(
        private val editor: SecretKeyRingEditor,
        private val keyId: KeyIdentifier?,
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
        private val keyId: KeyIdentifier?,
        private val oldProtector: SecretKeyRingProtector,
        private val newProtectionSettings: KeyRingProtectionSettings
    ) : SecretKeyRingEditorInterface.WithPassphrase {

        override fun toNewPassphrase(passphrase: Passphrase): SecretKeyRingEditorInterface {
            val protector =
                PasswordBasedSecretKeyRingProtector(
                    newProtectionSettings, SolitaryPassphraseProvider(passphrase))
            val secretKeys =
                changePassphrase(keyId, editor.key.pgpSecretKeyRing, oldProtector, protector)
            editor.key = editor.api.toKey(secretKeys)
            return editor
        }

        override fun toNoPassphrase(): SecretKeyRingEditorInterface {
            val protector = UnprotectedKeysProtector()
            val secretKeys =
                changePassphrase(keyId, editor.key.pgpSecretKeyRing, oldProtector, protector)
            editor.key = editor.api.toKey(secretKeys)
            return editor
        }
    }
}
