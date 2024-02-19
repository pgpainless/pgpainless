// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.io.InputStream
import java.util.Date
import org.bouncycastle.bcpg.attr.ImageAttribute
import org.bouncycastle.extensions.plusCertification
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.CertificationType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.implementation.ImplementationFactory
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
import org.pgpainless.util.Passphrase

class OpenPgpKeyGenerator internal constructor() {

    companion object {
        /**
         * Build a version 4 OpenPGP secret key.
         *
         * @param policy policy to ensure algorithm compliance and to determine default algorithms
         * @param creationTime creation time for the secret key
         * @param preferences suite of algorithm preferences and enabled features
         */
        @JvmStatic
        fun buildV4(
            policy: Policy = PGPainless.getPolicy(),
            creationTime: Date = Date(),
            preferences: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
        ): OpinionatedDefinePrimaryKeyV4 {
            return OpinionatedDefinePrimaryKeyV4(policy, creationTime, preferences)
        }
    }
}

/**
 * Builder that allows the user to define the primary key of the OpenPGP key.
 *
 * @param policy algorithm policy
 * @param creationTime default value for the creation time of the primary key.
 * @param preferences algorithm preferences
 * @param O versioned subkeys builder
 */
abstract class DefinePrimaryKey<O : DefineSubkeys<O>>
internal constructor(val policy: Policy, val creationTime: Date, val preferences: AlgorithmSuite) {

    // If set to true, no default direct-key signature will be added to the key
    internal var skipDefaultDirectKeySignature = false

    internal var keyFlags: List<KeyFlag>? = null

    internal abstract fun preferencesSubpackets(): SelfSignatureSubpackets.Callback

    internal abstract fun generatePrimaryKey(type: KeyType, creationTime: Date): PGPKeyPair

    internal abstract fun applyToPrimaryKey(
        primaryKey: PGPKeyPair,
        applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
    ): PGPKeyPair

    /**
     * Define the primary key for the OpenPGP key.
     *
     * @param type primary key type
     * @param keyFlags list of key flags that denote the primary keys capabilities
     * @param creationTime creation time of the primary key
     * @param applyToPrimaryKey function block to apply to the primary key
     * @return subkey builder
     */
    abstract fun setPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>? = listOf(KeyFlag.CERTIFY_OTHER),
        creationTime: Date = this.creationTime,
        applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)? = null
    ): O
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

    override fun applyToPrimaryKey(
        primaryKey: PGPKeyPair,
        applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
    ): PGPKeyPair {
        return if (applyToPrimaryKey == null) {
            primaryKey
        } else {
            ApplyToPrimaryKeyV4(primaryKey, this).applyToPrimaryKey()
        }
    }
}

/**
 * Interface for key builder that can be used to add additional subkeys to an OpenPGP key.
 *
 * @param primaryKey primary key of the OpenPGP key
 * @param policy policy to sanitize algorithms against
 * @param creationTime creation time of the OpenPGP key
 * @param subkeys list of subkeys that were already added
 * @param B type of this builder
 */
abstract class DefineSubkeys<B : DefineSubkeys<B>>
internal constructor(
    internal var primaryKey: PGPKeyPair,
    internal val policy: Policy,
    internal val creationTime: Date,
    internal val subkeys: MutableList<PGPKeyPair> = mutableListOf()
) {

    /**
     * Add a subkey to the OpenPGP key.
     *
     * @param type subkey type
     * @param creationTime creation time of the subkey
     * @param applyToSubkey function to apply to the subkey. Used to add binding signatures.
     * @return this
     */
    fun addSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)? = null
    ): B =
        apply {
            val subkey = generateSubkey(type, creationTime)
            subkeys.add(applyToSubkey(subkey, applyToSubkey))
        }
            as B

    internal abstract fun applyToSubkey(
        subkey: PGPKeyPair,
        applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)?
    ): PGPKeyPair

    internal abstract fun generateSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime
    ): PGPKeyPair

    /**
     * Finish the key generation and return the OpenPGP [PGPSecretKeyRing].
     *
     * @param protector protector to protect the OpenPGP key's secret components with
     * @return finished [PGPSecretKeyRing]
     */
    abstract fun build(
        protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    ): PGPSecretKeyRing

    /**
     * Finish the key generation and return the OpenPGP [PGPSecretKeyRing] protected with the given
     * [passphrase].
     *
     * @param passphrase passphrase to protect the OpenPGP key's secret components with
     * @return finished [PGPSecretKeyRing]
     */
    fun build(passphrase: Passphrase) = build(SecretKeyRingProtector.unlockAnyKeyWith(passphrase))
}

abstract class DefineSubkeysV4<O : DefineSubkeys<O>>(
    primaryKey: PGPKeyPair,
    policy: Policy,
    creationTime: Date,
    subkeys: List<PGPKeyPair>
) : DefineSubkeys<O>(primaryKey, policy, creationTime, subkeys.toMutableList()) {

    override fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair {
        return OpenPgpKeyPairGenerator.V4().generateSubkey(type, creationTime)
    }

    override fun applyToSubkey(
        subkey: PGPKeyPair,
        applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)?
    ): PGPKeyPair {
        return if (applyToSubkey == null) {
            subkey
        } else {
            ApplyToSubkeyV4(primaryKey, subkey, this).applyToSubkey()
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
                        protector.getEncryptor(primaryKey.keyID)))

                // Subkeys
                subkeys.forEach {
                    add(
                        PGPSecretKey(
                            it.privateKey,
                            it.publicKey,
                            ImplementationFactory.getInstance().v4FingerprintCalculator,
                            false,
                            protector.getEncryptor(it.keyID)))
                }
            })
    }
}

/**
 * Implementation of an [OpinionatedDefinePrimaryKey] for OpenPGP v4 keys.
 *
 * @param policy policy for algorithm compliance and fallbacks
 * @param creationTime creation time of the primary key
 */
class OpinionatedDefinePrimaryKeyV4
internal constructor(policy: Policy, creationTime: Date, preferences: AlgorithmSuite) :
    DefinePrimaryKeyV4<OpinionatedDefineSubkeysV4>(policy, creationTime, preferences) {

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

    override fun setPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>?,
        creationTime: Date,
        applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
    ): OpinionatedDefineSubkeysV4 {
        // Check algorithm is signing capable
        require(type.algorithm.isSigningCapable()) { "Primary Key MUST be capable of signing." }

        // Check key strength
        require(policy.publicKeyAlgorithmPolicy.isAcceptable(type.algorithm, type.bitStrength)) {
            "Public Key algorithm ${type.algorithm} with ${type.bitStrength} is too weak" +
                " for the current public key algorithm policy."
        }

        // Remember flags for DK and UID signatures
        this.keyFlags = keyFlags

        // Add user-provided signatures
        var key = applyToPrimaryKey(generatePrimaryKey(type, creationTime), applyToPrimaryKey)

        // If no DK sig has been added by user, add default DK sig
        if (!skipDefaultDirectKeySignature) {
            key = applyToPrimaryKey(key) { addDirectKeySignature(preferencesSubpackets()) }
        }

        return OpinionatedDefineSubkeysV4(key, policy, creationTime)
    }
}

/**
 * Implementation of an [UnopinionatedDefinePrimaryKey] for OpenPGP v4 keys.
 *
 * @param creationTime creation time of the primary key
 */
class UnopinionatedDefinePrimaryKeyV4
internal constructor(policy: Policy, creationTime: Date, preferences: AlgorithmSuite) :
    DefinePrimaryKeyV4<UnopinionatedDefineSubkeysV4>(policy, creationTime, preferences) {

    constructor(
        opinionated: OpinionatedDefinePrimaryKeyV4
    ) : this(opinionated.policy, opinionated.creationTime, opinionated.preferences)

    override fun preferencesSubpackets(): SelfSignatureSubpackets.Callback =
        SelfSignatureSubpackets.nop()

    override fun setPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>?,
        creationTime: Date,
        applyToPrimaryKey: (ApplyToPrimaryKey.() -> PGPKeyPair)?
    ): UnopinionatedDefineSubkeysV4 {

        // Remember flags for DK and UID signatures
        // this.keyFlags = keyFlags

        // Add user-provided signatures
        val key = applyToPrimaryKey(generatePrimaryKey(type, creationTime), applyToPrimaryKey)

        // return builder for adding subkeys
        return UnopinionatedDefineSubkeysV4(key, policy, creationTime)
    }
}

/**
 * Implementation of an [OpinionatedDefineSubkeys] builder for version 4 OpenPGP keys.
 *
 * @param primaryKey version 4 OpenPGP primary key
 * @param policy policy
 * @param creationTime creation time of the OpenPGP key
 * @param unopinionated unopinionated variant of this builder
 */
class OpinionatedDefineSubkeysV4
internal constructor(primaryKey: PGPKeyPair, policy: Policy, creationTime: Date) :
    DefineSubkeysV4<OpinionatedDefineSubkeysV4>(primaryKey, policy, creationTime, listOf()) {

    fun unopinionated() = UnopinionatedDefineSubkeysV4(this)

    fun addSigningSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)? = {
            addBindingSignature(
                SelfSignatureSubpackets.applyHashed {
                    setSignatureCreationTime(creationTime)
                    setKeyFlags(KeyFlag.SIGN_DATA)
                })
        }
    ) = addSubkey(type, creationTime, applyToSubkey)

    fun addEncryptionSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)? = {
            addBindingSignature(
                SelfSignatureSubpackets.applyHashed {
                    setSignatureCreationTime(creationTime)
                    setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                })
        }
    ) = addSubkey(type, creationTime, applyToSubkey)
}

class UnopinionatedDefineSubkeysV4
internal constructor(
    primaryKey: PGPKeyPair,
    policy: Policy,
    creationTime: Date,
    subkeys: List<PGPKeyPair> = mutableListOf()
) : DefineSubkeysV4<UnopinionatedDefineSubkeysV4>(primaryKey, policy, creationTime, subkeys) {

    constructor(
        opinionated: OpinionatedDefineSubkeysV4
    ) : this(
        opinionated.primaryKey, opinionated.policy, opinionated.creationTime, opinionated.subkeys)

    override fun applyToSubkey(
        subkey: PGPKeyPair,
        applyToSubkey: (ApplyToSubkey.() -> PGPKeyPair)?
    ): PGPKeyPair {
        return if (applyToSubkey == null) {
            subkey
        } else {
            ApplyToSubkeyV4(primaryKey, subkey, this).applyToSubkey()
        }
    }

    override fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair {
        return OpenPgpKeyPairGenerator.V4().generateSubkey(type, creationTime)
    }
}

/**
 * Function that can be applied to the primary key.
 *
 * @param keyPair primary key pair
 * @param builder builder instance that generated the primary key
 */
abstract class ApplyToPrimaryKey
internal constructor(var keyPair: PGPKeyPair, val builder: DefinePrimaryKey<*>) {

    /**
     * Add a UserID to the primary key.
     *
     * @param userId UserID to be bound to the primary key
     * @param subpacketsCallback callback to modify the binding signatures subpackets
     * @param certificationType type of the certification signature. Defaults to
     *   [CertificationType.POSITIVE]
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param bindingTime creation time of the binding signature
     * @return modified key pair
     */
    abstract fun addUserId(
        userId: CharSequence,
        subpacketsCallback: SelfSignatureSubpackets.Callback = builder.preferencesSubpackets(),
        certificationType: CertificationType = CertificationType.POSITIVE,
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = builder.creationTime
    ): PGPKeyPair

    /**
     * Add a UserAttribute to the primary key.
     *
     * @param userAttribute UserAttribute to be bound to the primary key
     * @param subpacketsCallback callback to modify the binding signature subpackets
     * @param certificationType type of the binding signature. Default to
     *   [CertificationType.POSITIVE]
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param bindingTime creation time of the binding signature
     * @return modified key pair
     */
    abstract fun addUserAttribute(
        userAttribute: PGPUserAttributeSubpacketVector,
        subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
        certificationType: CertificationType = CertificationType.POSITIVE,
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = builder.creationTime
    ): PGPKeyPair

    /**
     * Add a JPEG image as UserAttribute to the primary key. This may for example be a profile
     * picture of the key owner.
     *
     * @param jpegInputStream input stream containing the JPEG encoded image
     * @param subpacketsCallback callback to modify the subpackets of the binding signature
     * @param certificationType type of the binding signature. Defaults to
     *   [CertificationType.POSITIVE]
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param bindingTime creation time of the binding signature
     * @return modified key pair
     */
    fun addImageAttribute(
        jpegInputStream: InputStream,
        subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
        certificationType: CertificationType = CertificationType.POSITIVE,
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = builder.creationTime
    ): PGPKeyPair =
        addUserAttribute(
            PGPUserAttributeSubpacketVectorGenerator()
                .apply { setImageAttribute(ImageAttribute.JPEG, Streams.readAll(jpegInputStream)) }
                .generate(),
            subpacketsCallback,
            certificationType,
            hashAlgorithm,
            bindingTime)

    /**
     * Add a DirectKeySignature to the primary key. Such a signature usually carries information
     * that applies to the whole OpenPGP key, such as algorithm preferences etc.
     */
    fun addDirectKeySignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback = builder.preferencesSubpackets(),
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = builder.creationTime
    ): PGPKeyPair {
        skipDefaultSignature()
        return doAddDirectKeySignature(subpacketsCallback, hashAlgorithm, bindingTime)
    }

    protected abstract fun doAddDirectKeySignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ): PGPKeyPair

    fun skipDefaultSignature(): PGPKeyPair {
        builder.skipDefaultDirectKeySignature = true
        return keyPair
    }

    /**
     * Schedule the execution of another [ApplyToPrimaryKey] function instance right after this one
     * has been executed.
     *
     * @param other second instance
     * @return modified key pair after this and [other] have been executed
     */
    abstract fun then(other: (ApplyToPrimaryKey.() -> PGPKeyPair)?): PGPKeyPair
}

class ApplyToPrimaryKeyV4 internal constructor(keyPair: PGPKeyPair, builder: DefinePrimaryKey<*>) :
    ApplyToPrimaryKey(keyPair, builder) {

    override fun addUserId(
        userId: CharSequence,
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        certificationType: CertificationType,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ): PGPKeyPair {
        val callback = markAsPrimaryIfNecessary(subpacketsCallback)

        val sig =
            buildCertificationFor(
                keyPair, userId, certificationType, bindingTime, hashAlgorithm, callback)

        keyPair = keyPair.plusCertification(userId, sig)
        return keyPair
    }

    private fun markAsPrimaryIfNecessary(
        subpacketsCallback: SelfSignatureSubpackets.Callback
    ): SelfSignatureSubpackets.Callback {
        val callback =
            // if key has primary User-IDs already, do nothing
            if (keyPair.publicKey.userIDs.asSequence().any { uid ->
                keyPair.publicKey.getSignaturesForID(uid).asSequence().any { sig ->
                    sig.hashedSubPackets.isPrimaryUserID
                }
            }) {
                subpacketsCallback
            } else {
                // else set this user-id as primary
                SelfSignatureSubpackets.applyHashed { setPrimaryUserId() }.then(subpacketsCallback)
            }
        return callback
    }

    override fun addUserAttribute(
        userAttribute: PGPUserAttributeSubpacketVector,
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        certificationType: CertificationType,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ): PGPKeyPair {
        val sig =
            buildCertificationFor(
                keyPair,
                userAttribute,
                certificationType,
                bindingTime,
                hashAlgorithm,
                subpacketsCallback)

        keyPair = keyPair.plusCertification(userAttribute, sig)
        return keyPair
    }

    override fun doAddDirectKeySignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ): PGPKeyPair {
        val sig =
            buildDirectKeySignature(
                keyPair,
                hashAlgorithm,
                subpacketsCallback.then(
                    SelfSignatureSubpackets.applyHashed { setSignatureCreationTime(bindingTime) }))
        keyPair = keyPair.plusCertification(sig)
        return keyPair
    }

    override fun then(other: (ApplyToPrimaryKey.() -> PGPKeyPair)?): PGPKeyPair {
        if (other != null) {
            keyPair = ApplyToPrimaryKeyV4(keyPair, builder).other()
        }
        return keyPair
    }

    /**
     * Build a certification signature that binds the given [userId] to the given primary key
     * [pair].
     *
     * @param pair primary key pair
     * @param userId UserID to be bound
     * @param certificationType type of the binding signature
     * @param bindingTime creation time of the binding signature
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param subpacketsCallback callback to modify the binding signatures subpackets
     * @return binding signature
     */
    private fun buildCertificationFor(
        pair: PGPKeyPair,
        userId: CharSequence,
        certificationType: CertificationType,
        bindingTime: Date,
        hashAlgorithm: HashAlgorithm,
        subpacketsCallback: SelfSignatureSubpackets.Callback
    ): PGPSignature {
        val builder =
            SelfSignatureBuilder(
                pair.privateKey, pair.publicKey, certificationType.signatureType, hashAlgorithm)
        builder.hashedSubpackets.apply { setSignatureCreationTime(bindingTime) }
        builder.applyCallback(subpacketsCallback)
        return builder.build(userId)
    }

    /**
     * Build a certification signature that binds the given [userAttribute] to the given primary key
     * [pair].
     *
     * @param pair primary key pair
     * @param userAttribute UserAttribute to be bound
     * @param certificationType type of the binding signature
     * @param bindingTime creation time of the binding signature
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param subpacketsCallback callback to modify the binding signatures subpackets
     * @return binding signature
     */
    private fun buildCertificationFor(
        pair: PGPKeyPair,
        userAttribute: PGPUserAttributeSubpacketVector,
        certificationType: CertificationType,
        bindingTime: Date,
        hashAlgorithm: HashAlgorithm,
        subpacketsCallback: SelfSignatureSubpackets.Callback
    ): PGPSignature {
        val builder =
            SelfSignatureBuilder(
                pair.privateKey, pair.publicKey, certificationType.signatureType, hashAlgorithm)
        builder.hashedSubpackets.apply { setSignatureCreationTime(bindingTime) }
        builder.applyCallback(subpacketsCallback)
        return builder.build(userAttribute)
    }

    /**
     * Build a DirectKey self signature over the primary key [pair].
     *
     * @param pair primary key pair
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param subpacketsCallback callback to modify the subpackets of the direct-key signature
     * @return direct-key self signature
     */
    private fun buildDirectKeySignature(
        pair: PGPKeyPair,
        hashAlgorithm: HashAlgorithm,
        subpacketsCallback: SelfSignatureSubpackets.Callback
    ): PGPSignature {
        val builder = DirectKeySelfSignatureBuilder(pair.privateKey, pair.publicKey, hashAlgorithm)

        builder.applyCallback(subpacketsCallback)

        return builder.build()
    }
}

/**
 * Function that can be applied to subkeys.
 *
 * @param primaryKey primary key pair
 * @param subkey subkey pair
 * @param builder builder instance that generated the subkey
 */
abstract class ApplyToSubkey
internal constructor(
    val primaryKey: PGPKeyPair,
    var subkey: PGPKeyPair,
    val builder: DefineSubkeys<*>
) {

    /**
     * Add a binding signature to the subkey.
     *
     * @param subpacketsCallback callback to modify the binding signatures subpackets
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param bindingTime creation time of the binding signature
     * @return modified subkey pair
     */
    abstract fun addBindingSignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
        hashAlgorithm: HashAlgorithm =
            builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
        bindingTime: Date = subkey.publicKey.creationTime
    ): PGPKeyPair
}

/**
 * Implementation of the [ApplyToSubkey] function tailored to OpenPGP v4 keys.
 *
 * @param primaryKey primary key pair
 * @param subkey subkey pair
 * @param builder builder instance that generated the subkey
 */
class ApplyToSubkeyV4
internal constructor(primaryKey: PGPKeyPair, subkey: PGPKeyPair, builder: DefineSubkeys<*>) :
    ApplyToSubkey(primaryKey, subkey, builder) {

    override fun addBindingSignature(
        subpacketsCallback: SelfSignatureSubpackets.Callback,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date
    ): PGPKeyPair {
        val sig =
            buildBindingSignature(
                primaryKey, subkey, hashAlgorithm, bindingTime, subpacketsCallback)

        subkey = subkey.plusCertification(sig)
        return subkey
    }

    /**
     * Generate a version 4 binding signature that binds the [subkey] to the [primaryKey].
     *
     * @param primaryKey primary key pair
     * @param subkey subkey pair
     * @param hashAlgorithm hash algorithm to be used during signature calculation
     * @param bindingTime creation time of the subkey
     * @param subpacketsCallback callback to modify the subpackets of the binding signature
     * @return subkey binding signature
     */
    private fun buildBindingSignature(
        primaryKey: PGPKeyPair,
        subkey: PGPKeyPair,
        hashAlgorithm: HashAlgorithm,
        bindingTime: Date,
        subpacketsCallback: SelfSignatureSubpackets.Callback
    ): PGPSignature {
        return SubkeyBindingSignatureBuilder(primaryKey, hashAlgorithm)
            .applyCallback(
                subpacketsCallback
                    .then(
                        SelfSignatureSubpackets.applyHashed {
                            setSignatureCreationTime(bindingTime)
                        })
                    .then(
                        SelfSignatureSubpackets.applyHashed {
                            if (isSigningCapable(getKeyFlags())) {
                                addEmbeddedSignature(
                                    PrimaryKeyBindingSignatureBuilder(subkey, hashAlgorithm)
                                        .build(primaryKey))
                            }
                        }))
            .build(subkey)
    }

    private fun isSigningCapable(flags: List<KeyFlag>?): Boolean {
        val signCapableFlags = listOf(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER)
        return flags?.any { signCapableFlags.contains(it) } ?: false
    }
}

/** Templates for OpenPGP key generation. */
class OpenPgpKeyTemplates private constructor() {

    companion object {

        /**
         * Templates for version 4 OpenPGP keys.
         *
         * @return templates
         */
        @JvmStatic fun v4() = V4()
    }

    /** Templates for version 4 OpenPGP keys. Version 4 keys are compliant to RFC4880. */
    class V4 internal constructor() {

        /**
         * Generate an OpenPGP key that consists of an Ed25519 primary key used for certification of
         * third-party keys, a dedicated Ed25519 subkey for message signing, and an X25519 subkey
         * used for message encryption.
         *
         * @param userId an arbitrary number of user-ids. The first UserID will be marked as primary
         * @param creationTime creation time for the OpenPGP key
         */
        fun ed25519Curve25519(
            vararg userId: CharSequence,
            creationTime: Date = Date()
        ): PGPSecretKeyRing =
            OpenPgpKeyGenerator.buildV4(creationTime = creationTime)
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    // Add UserIDs
                    userId.forEachIndexed { index, uid ->
                        if (index == 0) {
                            // Mark first UserID as primary
                            addUserId(
                                uid, SelfSignatureSubpackets.applyHashed { setPrimaryUserId() })
                        } else {
                            addUserId(uid)
                        }
                    }
                    // Add Direct-Key signature with preferences and keyFlags
                    addDirectKeySignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.CERTIFY_OTHER) })
                }
                // singing key
                .addSubkey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.SIGN_DATA) })
                }
                // encryption key
                .addSubkey(KeyType.XDH(XDHSpec._X25519)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed {
                            setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                        })
                }
                .build()

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
            length: RsaLength = RsaLength._4096
        ): PGPSecretKeyRing =
            OpenPgpKeyGenerator.buildV4(creationTime = creationTime)
                .setPrimaryKey(KeyType.RSA(length)) {
                    // Add UserIDs
                    userId.forEachIndexed { index, uid ->
                        if (index == 0) {
                            // Mark first UserID as primary
                            addUserId(
                                uid, SelfSignatureSubpackets.applyHashed { setPrimaryUserId() })
                        } else {
                            addUserId(uid)
                        }
                    }
                    // Add Direct-Key signature with preferences and keyFlags
                    addDirectKeySignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.CERTIFY_OTHER) })
                }
                // signing key
                .addSubkey(KeyType.RSA(length)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed { setKeyFlags(KeyFlag.SIGN_DATA) })
                }
                // encryption key
                .addSubkey(KeyType.RSA(length)) {
                    addBindingSignature(
                        SelfSignatureSubpackets.applyHashed {
                            setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                        })
                }
                .build()

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
            length: RsaLength = RsaLength._4096
        ): PGPSecretKeyRing =
            OpenPgpKeyGenerator.buildV4(creationTime = creationTime)
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
                .build()
    }
}
