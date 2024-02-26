// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.io.InputStream
import java.util.*
import openpgp.formatUTC
import org.bouncycastle.bcpg.attr.ImageAttribute
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.CertificationType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.plusCertification
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.DefinePrimaryKey.PrimaryKeyBuilder
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
import org.pgpainless.util.Passphrase

typealias PrimaryKeyBlock = (PrimaryKeyBuilder.() -> Unit)

typealias SubkeyBlock = (SubkeyBuilder.() -> Unit)

/**
 * API for generating OpenPGP keys. The API allows to generate keys of different OpenPGP protocol
 * versions (currently only v4). The API is divided into an opinionated and unopinionated
 * implementation.
 *
 * The opinionated implementation will sanitize algorithms and key sizes and will furthermore make
 * sure that required signatures (e.g. direct-key or binding signatures) are placed on the key,
 * while the unopinionated API allows for the use of weak algorithms and does not add any signatures
 * by itself.
 *
 * You can switch from the opinionated API to the unopinionated API by calling `unopinionated()` on
 * the builder.
 */
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
        @JvmOverloads
        fun buildV4Key(
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
    protected var skipDefaultDirectKeySignature = false

    // The key flags are set with the setPrimaryKey method
    // It can be reused (e.g. by the v4 builder) to populate direct-key and self-certification
    //  signatures with the intended key flags.
    protected var keyFlags: List<KeyFlag>? = null

    /**
     * Callback to set preferences on the key and user-ids, such as algorithm preferences, features
     * etc. This callback will be used to modify direct-key signatures and bindings for user-ids.
     *
     * @return callback
     */
    protected abstract fun preferencesSubpackets(): SelfSignatureSubpackets.Callback

    /**
     * Builder-provided subpackets for direct-key signatures.
     *
     * @return callback
     */
    protected fun directKeySignatureSubpackets() = preferencesSubpackets()

    /**
     * Builder-provided subpackets for UserID binding signatures.
     *
     * @param primaryKey primary key
     * @return callback
     */
    protected abstract fun userIdSubpackets(
        primaryKey: PGPKeyPair
    ): SelfSignatureSubpackets.Callback

    /**
     * Builder-provided subpackets for UserAttribute binding signatures.
     *
     * @param primaryKey primary key
     * @return callback
     */
    protected abstract fun userAttributeSubpackets(
        primaryKey: PGPKeyPair
    ): SelfSignatureSubpackets.Callback

    /**
     * Generate an OpenPGP primary key.
     *
     * @return primary key
     */
    protected abstract fun generatePrimaryKey(type: KeyType, creationTime: Date): PGPKeyPair

    /**
     * Apply a [PrimaryKeyBuilder] instance to the given [PGPKeyPair].
     *
     * @return altered [PGPKeyPair]
     */
    protected abstract fun invokeOnPrimaryKey(
        primaryKey: PGPKeyPair,
        block: PrimaryKeyBlock?
    ): PGPKeyPair

    /**
     * Define the primary key for the OpenPGP key. The [block] function block can be used to add
     * UserIDs and preferences to the key. Example:
     * ```
     * setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
     *     addDirectKeySignature(...)
     *     addUserId("Alice <alice@example.com>") // first user-id is primary
     *     addUserId("Bob <bob@example.com>")
     * }
     * ```
     *
     * @param type primary key type
     * @param keyFlags list of key flags that denote the primary keys capabilities
     * @param creationTime creation time of the primary key
     * @param block function block to apply to the primary key
     * @return subkey builder
     */
    @JvmOverloads
    fun setPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>? = listOf(KeyFlag.CERTIFY_OTHER),
        creationTime: Date = this.creationTime,
        block: PrimaryKeyBlock? = null
    ): O {
        require(type.canCertify) {
            "Primary key cannot use algorithm ${type.algorithm} because it needs to be " +
                "signing capable."
        }
        return doSetPrimaryKey(type, keyFlags, creationTime, block)
    }

    fun setPrimaryKey(type: KeyType, block: PrimaryKeyBlock?): O =
        setPrimaryKey(type, listOf(KeyFlag.CERTIFY_OTHER), this.creationTime, block)

    protected abstract fun doSetPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>?,
        creationTime: Date,
        block: PrimaryKeyBlock?
    ): O

    /**
     * Sanitize the [HashAlgorithm] used for creating a signature by comparing it to the [Policy].
     *
     * @param algorithm hash algorithm
     */
    protected open fun sanitizeHashAlgorithm(algorithm: HashAlgorithm) {
        // Do nothing
    }

    /**
     * Sanitize the creation time of a self-certification signature.
     *
     * @param bindingTime signature creation time
     * @param primaryKey primary key
     */
    protected open fun sanitizeBindingTime(bindingTime: Date, primaryKey: PGPKeyPair) {
        // Do nothing
    }

    protected open fun sanitizeKeyFlags(algorithm: PublicKeyAlgorithm, keyFlags: List<KeyFlag>?) {
        // Do nothing
    }

    /**
     * Function that can be applied to the primary key.
     *
     * @param keyPair primary key pair
     * @param builder builder instance that generated the primary key
     */
    abstract class PrimaryKeyBuilder
    protected constructor(
        protected var keyPair: PGPKeyPair,
        protected val builder: DefinePrimaryKey<*>
    ) {

        /**
         * Add a UserID to the primary key.
         *
         * @param userId UserID to be bound to the primary key
         * @param subpacketsCallback callback to modify the binding signatures subpackets Note: The
         *   user-provided changes are applied over builder-provided subpackets
         * @param certificationType type of the certification signature. Defaults to
         *   [CertificationType.POSITIVE]
         * @param hashAlgorithm hash algorithm to be used during signature calculation
         * @param bindingTime creation time of the binding signature
         */
        @JvmOverloads
        fun addUserId(
            userId: CharSequence,
            subpacketsCallback: SelfSignatureSubpackets.Callback = builder.preferencesSubpackets(),
            certificationType: CertificationType = CertificationType.POSITIVE,
            hashAlgorithm: HashAlgorithm =
                builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            bindingTime: Date = builder.creationTime
        ) {
            builder.sanitizeHashAlgorithm(hashAlgorithm)
            builder.sanitizeBindingTime(bindingTime, keyPair)

            val callback = builder.userIdSubpackets(keyPair).then(subpacketsCallback)
            doAddUserId(userId, callback, certificationType, hashAlgorithm, bindingTime)
        }

        /**
         * Actually add a UserID to the primary key.
         *
         * @param userId UserId
         * @param subpacketsCallback callback to modify the subpackets of the binding signature with
         * @param certificationType signature type of the binding signature (certification level)
         * @param hashAlgorithm hash algorithm to be used to calculate the signature
         * @param bindingTime creation time of the binding signature
         */
        protected abstract fun doAddUserId(
            userId: CharSequence,
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            certificationType: CertificationType,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        )

        /**
         * Add a UserAttribute to the primary key.
         *
         * @param userAttribute UserAttribute to be bound to the primary key
         * @param subpacketsCallback user-provided callback to modify the binding signature
         *   subpackets Note: The user-provided changes are applied over subpackets provided by the
         *   builder
         * @param certificationType type of the binding signature. Default to
         *   [CertificationType.POSITIVE]
         * @param hashAlgorithm hash algorithm to be used during signature calculation
         * @param bindingTime creation time of the binding signature
         */
        @JvmOverloads
        fun addUserAttribute(
            userAttribute: PGPUserAttributeSubpacketVector,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
            certificationType: CertificationType = CertificationType.POSITIVE,
            hashAlgorithm: HashAlgorithm =
                builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            bindingTime: Date = builder.creationTime
        ) {
            builder.sanitizeHashAlgorithm(hashAlgorithm)
            builder.sanitizeBindingTime(bindingTime, keyPair)

            val callback = builder.userAttributeSubpackets(keyPair).then(subpacketsCallback)
            doAddUserAttribute(
                userAttribute, callback, certificationType, hashAlgorithm, bindingTime)
        }

        /**
         * Actually add the UserAttribute to the primary key.
         *
         * @param userAttribute UserAttribute to be added to the primary key
         * @param subpacketsCallback callback to modify the subpackets of the binding signature with
         * @param certificationType signature type (certification level)
         * @param hashAlgorithm hash algorithm to calculate the binding signature with
         * @param bindingTime creation time of the binding signature
         */
        protected abstract fun doAddUserAttribute(
            userAttribute: PGPUserAttributeSubpacketVector,
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            certificationType: CertificationType,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        )

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
         */
        @JvmOverloads
        fun addImageAttribute(
            jpegInputStream: InputStream,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
            certificationType: CertificationType = CertificationType.POSITIVE,
            hashAlgorithm: HashAlgorithm =
                builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            bindingTime: Date = builder.creationTime
        ) =
            addUserAttribute(
                PGPUserAttributeSubpacketVectorGenerator()
                    .apply {
                        setImageAttribute(ImageAttribute.JPEG, Streams.readAll(jpegInputStream))
                    }
                    .generate(),
                subpacketsCallback,
                certificationType,
                hashAlgorithm,
                bindingTime)

        /**
         * Add a DirectKeySignature to the primary key. Such a signature usually carries information
         * that applies to the whole OpenPGP key, such as algorithm preferences etc.
         *
         * @param subpacketsCallback callback to modify the direct-key signatures subpackets with
         *   Note, that the user-provided changed subpackets are applied over builder-provided
         *   subpackets.
         * @param hashAlgorithm hash algorithm to calculate the signature with
         * @param bindingTime signature creation time
         */
        @JvmOverloads
        fun addDirectKeySignature(
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
            hashAlgorithm: HashAlgorithm =
                builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            bindingTime: Date = builder.creationTime
        ) {
            builder.sanitizeHashAlgorithm(hashAlgorithm)
            builder.sanitizeBindingTime(bindingTime, keyPair)

            skipDefaultSignature()
            val callback = builder.directKeySignatureSubpackets().then(subpacketsCallback)
            doAddDirectKeySignature(callback, hashAlgorithm, bindingTime)
        }

        /**
         * Actually add a direct-key signature to the primary key.
         *
         * @param subpacketsCallback callback to modify the direct-key signatures subpackets with
         * @param hashAlgorithm hash algorithm to calculate the signature with
         * @param bindingTime creation time for the direct-key signature
         */
        protected abstract fun doAddDirectKeySignature(
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        )

        /** Do not add the default direct-key signature automatically. */
        fun skipDefaultSignature() {
            builder.skipDefaultDirectKeySignature = true
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
     * @param block function to apply to the subkey. Used to add binding signatures.
     * @return this
     */
    @Suppress("UNCHECKED_CAST")
    @JvmOverloads
    fun addSubkey(
        type: KeyType,
        flags: List<KeyFlag>? = null,
        creationTime: Date = this.creationTime,
        block: SubkeyBlock? = null
    ): B =
        apply {
            sanitizeKeyFlags(type.algorithm, flags)
            sanitizeSubkeyCreationTime(creationTime, primaryKey)

            var subkey = generateSubkey(type, creationTime)
            val subkeyBlock =
                block
                    ?: {
                        addBindingSignature(
                            SelfSignatureSubpackets.applyHashed { flags?.let { setKeyFlags(it) } },
                            bindingTime = creationTime)
                    }
            subkey = invokeOnSubkey(subkey, subkeyBlock)
            subkeys.add(subkey)
        }
            as B

    /**
     * Apply the given [block] function block to the given [subkey].
     *
     * @param subkey subkey
     * @param block function block
     * @return modified subkey
     */
    protected abstract fun invokeOnSubkey(subkey: PGPKeyPair, block: SubkeyBlock?): PGPKeyPair

    /**
     * Generate an OpenPGP subkey.
     *
     * @param type subkey type
     * @param creationTime subkey creation time
     */
    protected abstract fun generateSubkey(
        type: KeyType,
        creationTime: Date = this.creationTime
    ): PGPKeyPair

    /**
     * Finish the key generation and return the OpenPGP [PGPSecretKeyRing].
     *
     * @param protector protector to protect the OpenPGP key's secret components with
     * @return finished [PGPSecretKeyRing]
     */
    abstract fun build(protector: SecretKeyRingProtector): PGPSecretKeyRing

    /**
     * Finish the key generation and return the OpenPGP [PGPSecretKeyRing] protected with the given
     * [passphrase].
     *
     * @param passphrase passphrase to protect the OpenPGP key's secret components with
     * @return finished [PGPSecretKeyRing]
     */
    fun build(passphrase: Passphrase) = build(SecretKeyRingProtector.unlockAnyKeyWith(passphrase))

    fun build() = build(SecretKeyRingProtector.unprotectedKeys())

    /**
     * Sanitize the [HashAlgorithm] used for creating a signature by comparing it to the [Policy].
     *
     * @param algorithm hash algorithm
     */
    protected open fun sanitizeHashAlgorithm(algorithm: HashAlgorithm) {
        // Do nothing
    }

    /**
     * Sanitize the signature creation time of a subkey binding signature.
     *
     * @param bindingTime creation time of the binding signature
     * @param subkey subkey
     */
    protected open fun sanitizeBindingTime(bindingTime: Date, subkey: PGPKeyPair) {
        // Do nothing
    }

    /**
     * Sanitize the creation time of the subkey.
     *
     * @param subkeyCreationTime creation time of the subkey
     * @param primaryKey primary key
     */
    protected open fun sanitizeSubkeyCreationTime(
        subkeyCreationTime: Date,
        primaryKey: PGPKeyPair
    ) {
        // Do nothing
    }

    protected open fun sanitizeKeyFlags(algorithm: PublicKeyAlgorithm, keyFlags: List<KeyFlag>?) {
        // Do nothing
    }

    /**
     * Function that can be applied to subkeys.
     *
     * @param primaryKey primary key pair
     * @param subkey subkey pair
     * @param builder builder instance that generated the subkey
     */
    abstract class SubkeyBuilder
    internal constructor(
        protected val primaryKey: PGPKeyPair,
        protected var subkey: PGPKeyPair,
        protected val builder: DefineSubkeys<*>
    ) {

        /**
         * Add a binding signature to the subkey.
         *
         * @param subpacketsCallback callback to modify the binding signatures subpackets
         * @param hashAlgorithm hash algorithm to be used during signature calculation
         * @param bindingTime creation time of the binding signature
         * @return modified subkey pair
         */
        @JvmOverloads
        fun addBindingSignature(
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop(),
            hashAlgorithm: HashAlgorithm =
                builder.policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            bindingTime: Date = subkey.publicKey.creationTime
        ) {
            builder.sanitizeHashAlgorithm(hashAlgorithm)
            builder.sanitizeBindingTime(bindingTime, subkey)

            doAddBindingSignature(subpacketsCallback, hashAlgorithm, bindingTime)
        }

        abstract fun doAddBindingSignature(
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        )
    }
}

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
        policy: Policy,
        creationTime: Date,
        subkeys: List<PGPKeyPair>
    ) : DefineSubkeys<O>(primaryKey, policy, creationTime, subkeys.toMutableList()) {

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

        return OpinionatedDefineSubkeysV4(primaryKey, policy, creationTime)
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
        return UnopinionatedDefineSubkeysV4(primaryKey, policy, creationTime)
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
internal constructor(primaryKey: PGPKeyPair, policy: Policy, creationTime: Date) :
    SubkeyBuilderV4.DefineSubkeysV4<OpinionatedDefineSubkeysV4>(
        primaryKey, policy, creationTime, listOf()) {

    /**
     * Return an unopinionated implementation of this builder.
     *
     * @return unopinionated builder
     */
    fun unopinionated() = UnopinionatedDefineSubkeysV4(this)

    /**
     * Add a subkey for signing messages to the OpenPGP key.
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
     * Add a subkey for signing messages to the OpenPGP key.
     *
     * @param type signing key type
     * @param block function block to add binding signatures to the subkey
     */
    fun addSigningSubkey(type: KeyType, block: SubkeyBlock?) =
        addSigningSubkey(type, this.creationTime, block)

    /**
     * Add a subkey for message encryption to the OpenPGP key.
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
     * Add a subkey for message encryption to the OpenPGP key.
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
    policy: Policy,
    creationTime: Date,
    subkeys: List<PGPKeyPair> = mutableListOf()
) :
    SubkeyBuilderV4.DefineSubkeysV4<UnopinionatedDefineSubkeysV4>(
        primaryKey, policy, creationTime, subkeys) {

    /**
     * Constructor to build an unopinionated variant of the given [OpinionatedDefineSubkeysV4].
     *
     * @param opinionated opinionated builder
     */
    internal constructor(
        opinionated: OpinionatedDefineSubkeysV4
    ) : this(
        opinionated.primaryKey, opinionated.policy, opinionated.creationTime, opinionated.subkeys)

    override fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair {
        return OpenPgpKeyPairGenerator.V4().generateSubkey(type, creationTime)
    }
}

/** Implementation of [DefinePrimaryKey.PrimaryKeyBuilder] tailored to version 4 OpenPGP keys. */
class PrimaryKeyBuilderV4 internal constructor(keyPair: PGPKeyPair, builder: DefinePrimaryKey<*>) :
    PrimaryKeyBuilder(keyPair, builder) {

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
            OpenPgpKeyGenerator.buildV4Key(creationTime = creationTime)
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
                .addSigningSubkey(KeyType.EDDSA(EdDSACurve._Ed25519))
                // encryption key
                .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
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
            OpenPgpKeyGenerator.buildV4Key(creationTime = creationTime)
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
                .addSigningSubkey(KeyType.RSA(length))
                // encryption key
                .addEncryptionSubkey(KeyType.RSA(length))
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
            OpenPgpKeyGenerator.buildV4Key(creationTime = creationTime)
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
