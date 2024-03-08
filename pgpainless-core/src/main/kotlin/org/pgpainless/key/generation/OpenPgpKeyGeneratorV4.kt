// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.util.*
import openpgp.formatUTC
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.CertificationType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.plusCertification
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.DefineSubkeys.SubkeyBuilder
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import org.pgpainless.signature.builder.DirectKeySelfSignatureBuilder
import org.pgpainless.signature.builder.PrimaryKeyBindingSignatureBuilder
import org.pgpainless.signature.builder.SelfSignatureBuilder
import org.pgpainless.signature.builder.SubkeyBindingSignatureBuilder
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

/**
 * Implementation of the [SubkeyBuilder] function tailored to OpenPGP v4 keys.
 *
 * @param primaryKey primary key pair
 * @param subkey subkey pair
 * @param builder builder instance that generated the subkey
 */
class SubkeyBuilderV4
internal constructor(primaryKey: PGPKeyPair, subkey: PGPKeyPair, builder: DefineSubkeys<*>) :
    SubkeyBuilder(primaryKey, subkey, builder) {

    override fun doAddBindingSignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ) {
        val sigBuilder = SubkeyBindingSignatureBuilder(primaryKey, hashAlgorithm)
        sigBuilder.applyCallback(
            // sets key flags
            subpacketsCallback
                .then(setCreationTime(bindingTime))
                // adds back sig if key flags contain sign or certify
                .then(addBackSignatureIfNecessary(hashAlgorithm)))
        val sig = sigBuilder.build(subkey)

        subkey = subkey.plusCertification(sig)
    }

    /**
     * Return a [SelfSignatureSubpackets.Callback] that sets the signature creation time to the
     * given [bindingTime].
     *
     * @param bindingTime signature creation time
     * @return callback
     */
    private fun setCreationTime(bindingTime: Date): SelfSignatureSubpackets.Callback {
        return SelfSignatureSubpackets.applyHashed { setSignatureCreationTime(bindingTime) }
    }

    /**
     * Return a [SelfSignatureSubpackets.Callback] that adds a PrimaryKeyBinding Signature
     * (back-signature) if the subkey is signing capable.
     *
     * @param hashAlgorithm hash algorithm to calculate the back-sig with
     * @return callback
     */
    private fun addBackSignatureIfNecessary(
        hashAlgorithm: HashAlgorithm
    ): SelfSignatureSubpackets.Callback {
        return SelfSignatureSubpackets.applyHashed {
            if (isSigningCapable(getKeyFlags())) {
                addEmbeddedSignature(
                    PrimaryKeyBindingSignatureBuilder(subkey, hashAlgorithm).build(primaryKey))
            }
        }
    }

    /**
     * Return `true` if the given [flags] list contains either [KeyFlag.SIGN_DATA] or
     * [KeyFlag.CERTIFY_OTHER].
     *
     * @return true if contains SIGN_DATA or CERTIFY_OTHER
     */
    private fun isSigningCapable(flags: List<KeyFlag>?): Boolean =
        flags.orEmpty().contains(KeyFlag.SIGN_DATA) ||
            flags.orEmpty().contains(KeyFlag.CERTIFY_OTHER)

    /**
     * Implementation of [DefineSubkeys] tailored to version 4 OpenPGP keys.
     *
     * @param primaryKey primary key
     * @param policy policy
     * @param creationTime creation time of the OpenPGP key
     * @param subkeys list of already added subkeys
     */
    abstract class DefineSubkeysV4<O : DefineSubkeys<O>>(
        primaryKey: PGPKeyPair,
        primaryKeyProtector: SecretKeyRingProtector?,
        policy: Policy,
        creationTime: Date,
        subkeys: List<PGPKeyPair>
    ) :
        DefineSubkeys<O>(
            primaryKey, primaryKeyProtector, policy, creationTime, subkeys.toMutableList()) {

        override fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair {
            return OpenPgpKeyPairGenerator.V4().generateSubkey(type, creationTime)
        }

        override fun invokeOnSubkey(subkey: PGPKeyPair, block: SubkeyBlock?): PGPKeyPair {
            return with(SubkeyBuilderV4(primaryKey, subkey, this)) {
                if (block != null) {
                    block()
                }
                this.subkey
            }
        }

        override fun build(protector: SecretKeyRingProtector): PGPSecretKeyRing {
            return PGPSecretKeyRing(
                buildList {
                    // Primary Key
                    add(
                        PGPSecretKey(
                            primaryKey.privateKey,
                            primaryKey.publicKey,
                            ImplementationFactory.getInstance().v4FingerprintCalculator,
                            true,
                            (primaryKeyProtector ?: protector).getEncryptor(primaryKey.keyID)))

                    // Subkeys
                    subkeys.forEach {
                        add(
                            PGPSecretKey(
                                it.privateKey,
                                it.publicKey,
                                ImplementationFactory.getInstance().v4FingerprintCalculator,
                                false,
                                subkeyProtectors
                                    .getOrDefault(OpenPgpFingerprint.of(it), protector)
                                    .getEncryptor(it.keyID)))
                    }
                })
        }
    }
}

/**
 * Implementation of an opinionated [PrimaryKeyBuilderV4.DefinePrimaryKeyV4] builder.
 *
 * @param policy policy for algorithm compliance and fallbacks
 * @param creationTime creation time of the primary key
 * @param preferences algorithm preferences
 */
class OpinionatedDefinePrimaryKeyV4
internal constructor(policy: Policy, creationTime: Date, preferences: AlgorithmSuite) :
    PrimaryKeyBuilderV4.DefinePrimaryKeyV4<OpinionatedDefineSubkeysV4>(
        policy, creationTime, preferences) {

    /**
     * Return an unopinionated implementation of this builder.
     *
     * @return unopinionated builder
     */
    fun unopinionated() = UnopinionatedDefinePrimaryKeyV4(this)

    override fun preferencesSubpackets(): SelfSignatureSubpackets.Callback =
        SelfSignatureSubpackets.applyHashed {
            setSignatureCreationTime(creationTime)
            setPreferredHashAlgorithms(preferences.hashAlgorithms)
            setPreferredSymmetricKeyAlgorithms(preferences.symmetricKeyAlgorithms)
            setPreferredCompressionAlgorithms(preferences.compressionAlgorithms)
            setFeatures(preferences.features)
            keyFlags?.let { setKeyFlags(it) }
        }

    override fun userIdSubpackets(primaryKey: PGPKeyPair): SelfSignatureSubpackets.Callback {
        return preferencesSubpackets()
            .then(
                // if key has primary User-IDs already, do nothing
                if (primaryKey.publicKey.userIDs.asSequence().any { uid ->
                    primaryKey.publicKey.getSignaturesForID(uid).asSequence().any { sig ->
                        sig.hashedSubPackets.isPrimaryUserID
                    }
                }) {
                    SelfSignatureSubpackets.nop()
                } else {
                    // else set this user-id as primary
                    SelfSignatureSubpackets.applyHashed { setPrimaryUserId() }
                })
    }

    override fun userAttributeSubpackets(primaryKey: PGPKeyPair): SelfSignatureSubpackets.Callback {
        return preferencesSubpackets()
            .then(
                // if key has primary user-attributes already, do nothing
                if (primaryKey.publicKey.userAttributes.asSequence().any { attr ->
                    primaryKey.publicKey.getSignaturesForUserAttribute(attr).asSequence().any { sig
                        ->
                        sig.hashedSubPackets.isPrimaryUserID
                    }
                }) {
                    SelfSignatureSubpackets.nop()
                } else {
                    // else set this user-attribute as primary
                    SelfSignatureSubpackets.applyHashed { setPrimaryUserId() }
                })
    }

    override fun doSetPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>?,
        creationTime: Date,
        block: PrimaryKeyBlock?
    ): OpinionatedDefineSubkeysV4 {

        // Check key strength
        require(policy.publicKeyAlgorithmPolicy.isAcceptable(type.algorithm, type.bitStrength)) {
            "Public Key algorithm ${type.algorithm} with ${type.bitStrength} is too weak" +
                " for the current public key algorithm policy."
        }

        // Sanitize key flags
        sanitizeKeyFlags(type.algorithm, keyFlags)

        // Remember flags for DK and UID signatures
        this.keyFlags = keyFlags

        var primaryKey = generatePrimaryKey(type, creationTime)
        // Add user-provided signatures
        primaryKey = invokeOnPrimaryKey(primaryKey, block)

        // If no DK sig has been added by user, add default DK sig
        if (!skipDefaultDirectKeySignature) {
            primaryKey =
                invokeOnPrimaryKey(primaryKey) { addDirectKeySignature(preferencesSubpackets()) }
        }

        return OpinionatedDefineSubkeysV4(primaryKey, primaryKeyProtector, policy, creationTime)
    }

    override fun sanitizeHashAlgorithm(algorithm: HashAlgorithm) {
        require(policy.certificationSignatureHashAlgorithmPolicy.isAcceptable(algorithm)) {
            "Unacceptable Hash Algorithm. $algorithm cannot be used to generate self-certifications" +
                " as per the current hash algorithm policy."
        }
    }

    override fun sanitizeBindingTime(bindingTime: Date, primaryKey: PGPKeyPair) {
        require(!bindingTime.before(primaryKey.publicKey.creationTime)) {
            "Signature creation time predates primary key creation time. " +
                "Signature was created at ${bindingTime.formatUTC()}, " +
                "key was created at ${primaryKey.publicKey.creationTime.formatUTC()}."
        }
    }

    override fun sanitizeKeyFlags(algorithm: PublicKeyAlgorithm, keyFlags: List<KeyFlag>?) {
        keyFlags?.forEach { flag ->
            when (flag) {
                KeyFlag.CERTIFY_OTHER,
                KeyFlag.SIGN_DATA,
                KeyFlag.AUTHENTICATION ->
                    require(algorithm.isSigningCapable()) {
                        "Primary key cannot carry key flag $flag because the " +
                            "algorithm $algorithm is not signing capable."
                    }
                KeyFlag.ENCRYPT_COMMS,
                KeyFlag.ENCRYPT_STORAGE ->
                    require(algorithm.isEncryptionCapable()) {
                        "Primary key cannot carry key flag $flag because the " +
                            "algorithm $algorithm is not encryption capable."
                    }
                else -> {} // no special requirements for SPLIT and SHARED
            }
        }
    }
}

/**
 * Implementation of an unopinionated [PrimaryKeyBuilderV4.DefinePrimaryKeyV4] builder.
 *
 * @param policy policy
 * @param creationTime creation time of the primary key
 * @param preferences algorithm preferences
 */
class UnopinionatedDefinePrimaryKeyV4
internal constructor(policy: Policy, creationTime: Date, preferences: AlgorithmSuite) :
    PrimaryKeyBuilderV4.DefinePrimaryKeyV4<UnopinionatedDefineSubkeysV4>(
        policy, creationTime, preferences) {

    /**
     * Constructor for an unopinionated variant of the passed in [OpinionatedDefinePrimaryKeyV4].
     *
     * @param opinionated opinionated builder
     */
    internal constructor(
        opinionated: OpinionatedDefinePrimaryKeyV4
    ) : this(opinionated.policy, opinionated.creationTime, opinionated.preferences)

    override fun preferencesSubpackets(): SelfSignatureSubpackets.Callback =
        SelfSignatureSubpackets.nop()

    override fun userIdSubpackets(primaryKey: PGPKeyPair): SelfSignatureSubpackets.Callback {
        return preferencesSubpackets()
    }

    override fun userAttributeSubpackets(primaryKey: PGPKeyPair): SelfSignatureSubpackets.Callback {
        return preferencesSubpackets()
    }

    override fun doSetPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>?,
        creationTime: Date,
        block: PrimaryKeyBlock?
    ): UnopinionatedDefineSubkeysV4 {

        // Add user-provided signatures
        var primaryKey = generatePrimaryKey(type, creationTime)
        primaryKey = invokeOnPrimaryKey(primaryKey, block)

        // return builder for adding subkeys
        return UnopinionatedDefineSubkeysV4(primaryKey, primaryKeyProtector, policy, creationTime)
    }
}

/**
 * Implementation of an opinionated [SubkeyBuilderV4.DefineSubkeysV4] builder.
 *
 * @param primaryKey version 4 OpenPGP primary key
 * @param policy policy
 * @param creationTime creation time of the OpenPGP key
 */
class OpinionatedDefineSubkeysV4
internal constructor(
    primaryKey: PGPKeyPair,
    primaryKeyProtector: SecretKeyRingProtector?,
    policy: Policy,
    creationTime: Date
) :
    SubkeyBuilderV4.DefineSubkeysV4<OpinionatedDefineSubkeysV4>(
        primaryKey, primaryKeyProtector, policy, creationTime, listOf()) {

    /**
     * Return an unopinionated implementation of this builder.
     *
     * @return unopinionated builder
     */
    fun unopinionated() = UnopinionatedDefineSubkeysV4(this)

    /**
     * Add a subkey for signing messages to the OpenPGP key. If no explicit binding signature is set
     * inside [block], the key will be bound using a default binding signature marking the key as
     * signing capable.
     *
     * @param type signing key type
     * @param creationTime creation time of the signing subkey
     * @param block function block to add binding signatures to the subkey
     */
    @JvmOverloads
    fun addSigningSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        block: SubkeyBlock? = null
    ): OpinionatedDefineSubkeysV4 {
        return addSubkey(type, listOf(KeyFlag.SIGN_DATA), creationTime, block)
    }

    /**
     * Add a subkey for signing messages to the OpenPGP key. If no explicit binding signature is set
     * inside [block], the key will be bound using a default binding signature marking the key as
     * signing capable.
     *
     * @param type signing key type
     * @param block function block to add binding signatures to the subkey
     */
    fun addSigningSubkey(type: KeyType, block: SubkeyBlock?) =
        addSigningSubkey(type, this.creationTime, block)

    /**
     * Add a subkey for message encryption to the OpenPGP key. If no explicit binding signature is
     * set inside [block], the key will be bound using a default binding signature marking the key
     * as encryption capable.
     *
     * @param type encryption key type
     * @param creationTime creation time of the encryption key
     * @param block function block to add binding signatures to the subkey
     */
    @JvmOverloads
    fun addEncryptionSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        block: SubkeyBlock? = null,
    ): OpinionatedDefineSubkeysV4 {
        return addSubkey(
            type, listOf(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE), creationTime, block)
    }

    /**
     * Add a subkey for message encryption to the OpenPGP key. If no explicit binding signature is
     * set inside [block], the key will be bound using a default binding signature marking the key
     * as encryption capable.
     *
     * @param type encryption key type
     * @param block function block to add binding signatures to the subkey
     */
    fun addEncryptionSubkey(type: KeyType, block: SubkeyBlock?) =
        addEncryptionSubkey(type, this.creationTime, block)

    override fun sanitizeHashAlgorithm(algorithm: HashAlgorithm) {
        require(policy.certificationSignatureHashAlgorithmPolicy.isAcceptable(algorithm)) {
            "Unacceptable Hash Algorithm. $algorithm cannot be used to generate self-certifications" +
                " as per the current hash algorithm policy."
        }
    }

    override fun sanitizeBindingTime(bindingTime: Date, subkey: PGPKeyPair) {
        require(!bindingTime.before(subkey.publicKey.creationTime)) {
            "Creation time of binding signature predates subkey creation time. " +
                "Signature was created at ${bindingTime.formatUTC()}, " +
                "Subkey was created at ${subkey.publicKey.creationTime.formatUTC()}."
        }
    }

    override fun sanitizeSubkeyCreationTime(subkeyCreationTime: Date, primaryKey: PGPKeyPair) {
        require(!subkeyCreationTime.before(primaryKey.publicKey.creationTime)) {
            "Subkey creation time predates primary key creation time. " +
                "Subkey was created at ${subkeyCreationTime.formatUTC()}, " +
                "Primary key was created at ${primaryKey.publicKey.creationTime.formatUTC()}."
        }
    }

    override fun sanitizeKeyFlags(algorithm: PublicKeyAlgorithm, keyFlags: List<KeyFlag>?) {
        keyFlags?.forEach { flag ->
            when (flag) {
                KeyFlag.CERTIFY_OTHER,
                KeyFlag.SIGN_DATA,
                KeyFlag.AUTHENTICATION ->
                    require(algorithm.isSigningCapable()) {
                        "Subkey cannot carry key flag $flag because the " +
                            "algorithm $algorithm is not signing capable."
                    }
                KeyFlag.ENCRYPT_COMMS,
                KeyFlag.ENCRYPT_STORAGE ->
                    require(algorithm.isEncryptionCapable()) {
                        "Subkey cannot carry key flag $flag because the " +
                            "algorithm $algorithm is not encryption capable."
                    }
                else -> {} // no special requirements for SPLIT and SHARED
            }
        }
    }
}

/**
 * Unopinionated implementation of [SubkeyBuilderV4.DefineSubkeysV4].
 *
 * @param primaryKey primary key of the OpenPGP key
 * @param policy policy
 * @param creationTime creation time of the OpenPGP key
 * @param subkeys list of already added subkeys
 */
class UnopinionatedDefineSubkeysV4
internal constructor(
    primaryKey: PGPKeyPair,
    primaryKeyProtector: SecretKeyRingProtector?,
    policy: Policy,
    creationTime: Date,
    subkeys: List<PGPKeyPair> = mutableListOf()
) :
    SubkeyBuilderV4.DefineSubkeysV4<UnopinionatedDefineSubkeysV4>(
        primaryKey, primaryKeyProtector, policy, creationTime, subkeys) {

    /**
     * Constructor to build an unopinionated variant of the given [OpinionatedDefineSubkeysV4].
     *
     * @param opinionated opinionated builder
     */
    internal constructor(
        opinionated: OpinionatedDefineSubkeysV4
    ) : this(
        opinionated.primaryKey,
        opinionated.primaryKeyProtector,
        opinionated.policy,
        opinionated.creationTime,
        opinionated.subkeys)

    override fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair {
        return OpenPgpKeyPairGenerator.V4().generateSubkey(type, creationTime)
    }
}

/** Implementation of [DefinePrimaryKey.PrimaryKeyBuilder] tailored to version 4 OpenPGP keys. */
class PrimaryKeyBuilderV4 internal constructor(keyPair: PGPKeyPair, builder: DefinePrimaryKey<*>) :
    DefinePrimaryKey.PrimaryKeyBuilder(keyPair, builder) {

    override fun doAddUserId(
        userId: CharSequence,
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        certificationType: CertificationType,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ) {
        val builder =
            SelfSignatureBuilder(
                keyPair.privateKey,
                keyPair.publicKey,
                certificationType.signatureType,
                hashAlgorithm)
        builder.applyCallback(subpacketsCallback.then(setCreationTime(bindingTime)))
        val sig = builder.build(userId)

        keyPair = keyPair.plusCertification(userId, sig)
    }

    override fun doAddUserAttribute(
        userAttribute: PGPUserAttributeSubpacketVector,
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        certificationType: CertificationType,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ) {
        val builder =
            SelfSignatureBuilder(
                keyPair.privateKey,
                keyPair.publicKey,
                certificationType.signatureType,
                hashAlgorithm)
        builder.applyCallback(subpacketsCallback.then(setCreationTime(bindingTime)))
        val sig = builder.build(userAttribute)

        keyPair = keyPair.plusCertification(userAttribute, sig)
    }

    override fun doAddDirectKeySignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ) {
        val builder =
            DirectKeySelfSignatureBuilder(keyPair.privateKey, keyPair.publicKey, hashAlgorithm)
        builder.applyCallback(subpacketsCallback.then(setCreationTime(bindingTime)))
        val sig = builder.build()

        keyPair = keyPair.plusCertification(sig)
    }

    /**
     * Return a [SelfSignatureSubpackets.Callback] that sets the signature creation time to the
     * given [bindingTime].
     *
     * @param bindingTime signature creation time
     * @return callback
     */
    private fun setCreationTime(bindingTime: Date): SelfSignatureSubpackets.Callback {
        return SelfSignatureSubpackets.applyHashed { setSignatureCreationTime(bindingTime) }
    }

    /** Implementation of [DefinePrimaryKey] build for version 4 OpenPGP keys. */
    abstract class DefinePrimaryKeyV4<O : DefineSubkeys<O>>(
        policy: Policy,
        creationTime: Date,
        preferences: AlgorithmSuite
    ) : DefinePrimaryKey<O>(policy, creationTime, preferences) {

        override fun generatePrimaryKey(type: KeyType, creationTime: Date): PGPKeyPair {
            return OpenPgpKeyPairGenerator.V4().generatePrimaryKey(type, creationTime)
        }

        override fun invokeOnPrimaryKey(
            primaryKey: PGPKeyPair,
            block: PrimaryKeyBlock?
        ): PGPKeyPair {
            return with(PrimaryKeyBuilderV4(primaryKey, this)) {
                if (block != null) {
                    block()
                }
                this.keyPair
            }
        }

        override fun fromTemplate(): OpenPgpV4KeyTemplates = OpenPgpKeyTemplates.v4()
    }
}

/** Templates for version 4 OpenPGP keys. Version 4 keys are compliant to RFC4880. */
class OpenPgpV4KeyTemplates : OpenPgpKeyTemplates {

    /**
     * Generate an OpenPGP key that consists of an Ed25519 primary key used for certification of
     * third-party keys, a dedicated Ed25519 subkey for message signing, and an X25519 subkey used
     * for message encryption.
     *
     * @param userId an arbitrary number of user-ids. The first UserID will be marked as primary
     * @param creationTime creation time for the OpenPGP key
     */
    fun ed25519Curve25519(
        vararg userId: CharSequence,
        creationTime: Date = Date(),
        protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    ): PGPSecretKeyRing =
        OpenPgpKeyGenerator()
            .buildV4Key(creationTime = creationTime)
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                // Add UserIDs
                userId.forEachIndexed { index, uid ->
                    if (index == 0) {
                        // Mark first UserID as primary
                        addUserId(uid, SelfSignatureSubpackets.applyHashed { setPrimaryUserId() })
                    } else {
                        addUserId(uid)
                    }
                }
                // Add Direct-Key signature with preferences and keyFlags
                addDirectKeySignature(
                    SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.CERTIFY_OTHER) })
            }
            // singing key
            .addSigningSubkey(KeyType.EDDSA(EdDSACurve._Ed25519))
            // encryption key
            .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
            .build(protector)

    /**
     * Generate an OpenPGP key that consists of an RSA primary key used for certification of
     * third-party keys, a dedicated RSA subkey for message signing, and an RSA subkey used for
     * message encryption.
     *
     * @param userId an arbitrary number of user-ids. The first UserID will be marked as primary
     * @param creationTime creation time for the OpenPGP key
     * @param length RSA bit strength
     */
    fun composedRsa(
        vararg userId: CharSequence,
        creationTime: Date = Date(),
        length: RsaLength = RsaLength._4096,
        protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    ): PGPSecretKeyRing =
        OpenPgpKeyGenerator()
            .buildV4Key(creationTime = creationTime)
            .setPrimaryKey(KeyType.RSA(length)) {
                // Add UserIDs
                userId.forEachIndexed { index, uid ->
                    if (index == 0) {
                        // Mark first UserID as primary
                        addUserId(uid, SelfSignatureSubpackets.applyHashed { setPrimaryUserId() })
                    } else {
                        addUserId(uid)
                    }
                }
                // Add Direct-Key signature with preferences and keyFlags
                addDirectKeySignature(
                    SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.CERTIFY_OTHER) })
            }
            // signing key
            .addSigningSubkey(KeyType.RSA(length))
            // encryption key
            .addEncryptionSubkey(KeyType.RSA(length))
            .build(protector)

    /**
     * Generate an OpenPGP key consisting of a single RSA key that is used for certification of
     * third-party keys, signing and encryption of messages.
     *
     * @param userId an arbitrary number of UserIDs. The first one will be marked as primary.
     * @param creationTime creation time of the OpenPGP key
     * @param length bit-strength of the RSA key
     */
    fun singleRsa(
        vararg userId: CharSequence,
        creationTime: Date = Date(),
        length: RsaLength = RsaLength._4096,
        protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    ): PGPSecretKeyRing =
        OpenPgpKeyGenerator()
            .buildV4Key(creationTime = creationTime)
            .setPrimaryKey(KeyType.RSA(length)) {
                userId.forEach { addUserId(it) }
                addDirectKeySignature(
                    SelfSignatureSubpackets.applyHashed {
                        setKeyFlags(
                            KeyFlag.CERTIFY_OTHER,
                            KeyFlag.SIGN_DATA,
                            KeyFlag.ENCRYPT_COMMS,
                            KeyFlag.ENCRYPT_STORAGE)
                    })
            }
            .build(protector)
}
