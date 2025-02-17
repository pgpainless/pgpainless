// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring

import java.util.*
import java.util.function.Predicate
import javax.annotation.Nonnull
import kotlin.NoSuchElementException
import openpgp.openPgpKeyId
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.bcpg.sig.KeyExpirationTime
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyEditor
import org.bouncycastle.openpgp.api.SignatureParameters
import org.bouncycastle.openpgp.api.SignatureParameters.Callback
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction
import org.pgpainless.PGPainless
import org.pgpainless.PGPainless.Companion.inspectKeyRing
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator
import org.pgpainless.bouncycastle.extensions.getKeyExpirationDate
import org.pgpainless.bouncycastle.extensions.publicKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.requirePublicKey
import org.pgpainless.bouncycastle.extensions.toOpenPGPKey
import org.pgpainless.implementation.ImplementationFactory
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

class SecretKeyRingEditor(key: OpenPGPKey,
                          keyProtector: SecretKeyRingProtector,
                          override val referenceTime: Date = Date()
) : SecretKeyRingEditorInterface {

    private var editor: OpenPGPKeyEditor = OpenPGPKeyEditor(key, keyProtector, PGPainless.getInstance().implementation)

    constructor(
        secretKey: PGPSecretKeyRing,
        referenceTime: Date = Date(),
        keyProtector: SecretKeyRingProtector
    ) : this(secretKey.toOpenPGPKey(), keyProtector, referenceTime)

    override fun addUserId(
        userId: CharSequence,
        callback: SelfSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        val sanitizedUserId = sanitizeUserId(userId).toString()
        editor.addUserId(sanitizedUserId, object : Callback {
            override fun apply(parameters: SignatureParameters): SignatureParameters {
                return parameters.setSignatureCreationTime(referenceTime)
            }
        })
        return this
    }

    override fun addPrimaryUserId(
        userId: CharSequence,
    ): SecretKeyRingEditorInterface {
        val uid = sanitizeUserId(userId)
        val primaryKey = key.publicKey
        var info = inspectKeyRing(key, referenceTime)
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
            })

        // unmark previous primary user-ids to be non-primary
        info = inspectKeyRing(key, referenceTime)
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
                        })
                }
            }
        return this
    }

    override fun removeUserId(
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface {
        return revokeUserIds(
            RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                .withoutDescription(),
            predicate)
    }

    override fun removeUserId(
        userId: CharSequence
    ): SecretKeyRingEditorInterface {
        return removeUserId { uid -> userId == uid }
    }

    override fun replaceUserId(
        oldUserId: CharSequence,
        newUserId: CharSequence
    ): SecretKeyRingEditorInterface {
        val oldUID = sanitizeUserId(oldUserId)
        val newUID = sanitizeUserId(newUserId)
        require(oldUID.isNotBlank()) { "Old user-ID cannot be empty." }
        require(newUID.isNotBlank()) { "New user-ID cannot be empty." }

        val info = inspectKeyRing(key, referenceTime)
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
            })

        return revokeUserId(oldUID)
    }

    override fun addSubkey(
        keySpec: KeySpec,
        subkeyPassphrase: Passphrase
    ): SecretKeyRingEditorInterface {
        val callback =
            object : SelfSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    SignatureSubpacketsHelper.applyFrom(
                        keySpec.subpackets, hashedSubpackets as SignatureSubpackets)
                    hashedSubpackets.setSignatureCreationTime(referenceTime)
                }
            }
        return addSubkey(keySpec, subkeyPassphrase, callback)
    }

    override fun addSubkey(
        keySpec: KeySpec,
        subkeyPassphrase: Passphrase,
        callback: SelfSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        val version = OpenPGPKeyVersion.from(key.getPublicKey().version)
        val keyPair = KeyRingBuilder.generateKeyPair(keySpec, OpenPGPKeyVersion.v4, referenceTime)
        val subkeyProtector =
            PasswordBasedSecretKeyRingProtector.forKeyId(keyPair.keyIdentifier, subkeyPassphrase)
        val keyFlags = KeyFlag.fromBitmask(keySpec.subpackets.keyFlags).toMutableList()
        return addSubkey(
            keyPair,
            callback,
            subkeyProtector,
            keyFlags.removeFirst(),
            *keyFlags.toTypedArray())
    }

    override fun addSubkey(
        subkey: PGPKeyPair,
        callback: SelfSignatureSubpackets.Callback?,
        subkeyProtector: SecretKeyRingProtector,
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

        val primaryKey = key.secretKey
        val info = inspectKeyRing(key, referenceTime)
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
        key = KeyRingUtils.keysPlusSecretKey(key, secretSubkey)
        return this
    }

    override fun revoke(
        revocationAttributes: RevocationAttributes?
    ): SecretKeyRingEditorInterface {
        return revoke(callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun revoke(
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        editor.revokeKey(object : SignatureParameters.Callback {
            override fun apply(parameters: SignatureParameters?): SignatureParameters {
                if (callback != null) {
                    callback.modifyHashedSubpackets()
                }
            }
        })
    }

    override fun revokeSubkey(
        subkeyIdentifier: KeyIdentifier,
        revocationAttributes: RevocationAttributes?
    ): SecretKeyRingEditorInterface {
        return revokeSubkey(subkeyIdentifier, callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun revokeSubkey(
        subkeyId: Long,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        val revokeeSubKey = key.requirePublicKey(subkeyId)
        val subkeyRevocation = generateRevocation(revokeeSubKey, callback)
        key = injectCertification(key, revokeeSubKey, subkeyRevocation)
        return this
    }

    override fun revokeUserId(
        userId: CharSequence,
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
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        return revokeUserIds(callback, SelectUserId.exactMatch(sanitizeUserId(userId)))
    }

    override fun revokeUserIds(
        revocationAttributes: RevocationAttributes?,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface {
        return revokeUserIds(
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
        callback: RevocationSignatureSubpackets.Callback?,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface {
        selectUserIds(predicate)
            .also {
                if (it.isEmpty())
                    throw NoSuchElementException("No matching user-ids found on the key.")
            }
            .forEach { userId -> doRevokeUserId(userId, callback) }
        return this
    }

    override fun setExpirationDate(
        expiration: Date?
    ): SecretKeyRingEditorInterface {
        require(key.secretKey.isMasterKey) {
            "OpenPGP key does not appear to contain a primary secret key."
        }

        val prevDirectKeySig = getPreviousDirectKeySignature()
        // reissue direct key sig
        if (prevDirectKeySig != null) {
            key =
                injectCertification(
                    key,
                    key.publicKey,
                    reissueDirectKeySignature(expiration, prevDirectKeySig))
        }

        val primaryUserId = inspectKeyRing(key, referenceTime).getPossiblyExpiredPrimaryUserId()
        if (primaryUserId != null) {
            val prevUserIdSig = getPreviousUserIdSignatures(primaryUserId)
            val userIdSig =
                reissuePrimaryUserIdSig(expiration, primaryUserId, prevUserIdSig!!)
            key = injectCertification(key, primaryUserId, userIdSig)
        }

        val info = inspectKeyRing(key, referenceTime)
        for (userId in info.validUserIds) {
            if (userId == primaryUserId) {
                continue
            }

            val prevUserIdSig =
                info.getLatestUserIdCertification(userId)
                    ?: throw AssertionError(
                        "A valid user-id shall never have no user-id signature.")
            if (prevUserIdSig.hashedSubPackets.isPrimaryUserID) {
                key =
                    injectCertification(
                        key,
                        primaryUserId!!,
                        reissueNonPrimaryUserId(userId, prevUserIdSig))
            }
        }

        return this
    }

    override fun setExpirationDateOfSubkey(
        expiration: Date?,
        keyIdentifier: KeyIdentifier
    ): SecretKeyRingEditorInterface = apply {
        // is primary key
        if (keyId == key.publicKey.keyID) {
            return setExpirationDate(expiration)
        }

        // is subkey
        val subkey =
            key.getPublicKey(keyId)
                ?: throw NoSuchElementException("No subkey with ID ${keyId.openPgpKeyId()} found.")
        val prevBinding =
            inspectKeyRing(key).getCurrentSubkeyBindingSignature(keyId)
                ?: throw NoSuchElementException(
                    "Previous subkey binding signaure for ${keyId.openPgpKeyId()} MUST NOT be null.")
        val bindingSig = reissueSubkeyBindingSignature(subkey, expiration, prevBinding)
        key = injectCertification(key, subkey, bindingSig)
    }

    override fun createMinimalRevocationCertificate(
        revocationAttributes: RevocationAttributes?
    ): PGPPublicKeyRing {
        // Check reason
        if (revocationAttributes != null) {
            require(RevocationAttributes.Reason.isKeyRevocation(revocationAttributes.reason)) {
                "Revocation reason MUST be applicable to a key revocation."
            }
        }

        val revocation = createRevocation(revocationAttributes)
        var primaryKey = key.secretKey.publicKey
        primaryKey = KeyRingUtils.getStrippedDownPublicKey(primaryKey)
        primaryKey = PGPPublicKey.addCertification(primaryKey, revocation)
        return PGPPublicKeyRing(listOf(primaryKey))
    }

    override fun createRevocation(
        revocationAttributes: RevocationAttributes?
    ): PGPSignature {
        return generateRevocation(
            key.publicKey, callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun createRevocation(
        subkeyIdentifier: KeyIdentifier,
        revocationAttributes: RevocationAttributes?
    ): PGPSignature {
        return generateRevocation(
            key.requirePublicKey(subkeyId),
            callbackFromRevocationAttributes(revocationAttributes))
    }

    override fun createRevocation(
        subkeyIdentifier: KeyIdentifier,
        callback: RevocationSignatureSubpackets.Callback?
    ): PGPSignature {
        return generateRevocation(key.requirePublicKey(subkeyId), callback)
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
        return editor.done()
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
        revokeeSubkey: PGPPublicKey,
        callback: RevocationSignatureSubpackets.Callback?
    ): PGPSignature {
        val primaryKey = key.secretKey
        val signatureType =
            if (revokeeSubkey.isMasterKey) SignatureType.KEY_REVOCATION
            else SignatureType.SUBKEY_REVOCATION

        return RevocationSignatureBuilder(signatureType, primaryKey)
            .apply { applyCallback(callback) }
            .build(revokeeSubkey)
    }

    private fun doRevokeUserId(
        userId: CharSequence,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface {
        RevocationSignatureBuilder(SignatureType.CERTIFICATION_REVOCATION, key.secretKey)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(callback)
            }
            .let { key = injectCertification(key, userId, it.build(userId.toString())) }
        return this
    }

    private fun getPreviousDirectKeySignature(): PGPSignature? {
        val info = inspectKeyRing(key, referenceTime)
        return info.latestDirectKeySelfSignature
    }

    private fun getPreviousUserIdSignatures(userId: String): PGPSignature? {
        val info = inspectKeyRing(key, referenceTime)
        return info.getLatestUserIdCertification(userId)
    }

    @Throws(PGPException::class)
    private fun reissueNonPrimaryUserId(
        secretKeyRingProtector: SecretKeyRingProtector,
        userId: String,
        prevUserIdSig: PGPSignature
    ): PGPSignature {
        val builder = SelfSignatureBuilder(key.secretKey, secretKeyRingProtector, prevUserIdSig)
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
        return SelfSignatureBuilder(key.secretKey, secretKeyRingProtector, prevUserIdSig)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(
                    object : SelfSignatureSubpackets.Callback {
                        override fun modifyHashedSubpackets(
                            hashedSubpackets: SelfSignatureSubpackets
                        ) {
                            if (expiration != null) {
                                hashedSubpackets.setKeyExpirationTime(
                                    true, key.publicKey.creationTime, expiration)
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
            key.secretKey, secretKeyRingProtector, prevDirectKeySig)
            .apply {
                hashedSubpackets.setSignatureCreationTime(referenceTime)
                applyCallback(
                    object : SelfSignatureSubpackets.Callback {
                        override fun modifyHashedSubpackets(
                            hashedSubpackets: SelfSignatureSubpackets
                        ) {
                            if (expiration != null) {
                                hashedSubpackets.setKeyExpirationTime(
                                    key.publicKey.creationTime, expiration)
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
        val primaryKey = key.publicKey
        val secretPrimaryKey = key.secretKey
        val secretSubkey: PGPSecretKey? = key.getSecretKey(subkey.keyID)

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
        inspectKeyRing(key).validUserIds.filter { predicate.test(it) }

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
            val secretKeys = changePassphrase(keyId, editor.key, oldProtector, protector)
            editor.key = secretKeys
            return editor
        }

        override fun toNoPassphrase(): SecretKeyRingEditorInterface {
            val protector = UnprotectedKeysProtector()
            val secretKeys = changePassphrase(keyId, editor.key, oldProtector, protector)
            editor.key = secretKeys
            return editor
        }
    }
}
