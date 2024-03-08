// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.io.InputStream
import java.util.*
import org.bouncycastle.bcpg.attr.ImageAttribute
import org.bouncycastle.openpgp.PGPKeyPair
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
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.DefinePrimaryKey.PrimaryKeyBuilder
import org.pgpainless.key.generation.DefineSubkeys.SubkeyBuilder
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.util.Passphrase

/**
 * Function block that is applied to the OpenPGP [PrimaryKeyBuilder]. Within this block, you add
 * User-IDs, User-Attributes and Direct-Key signatures on the primary key.
 */
typealias PrimaryKeyBuilderBlock = (PrimaryKeyBuilder.() -> Unit)

/**
 * Function block that is applied to an OpenPGP [SubkeyBuilder]. Here you typically add
 * subkey-binding signatures.
 */
typealias SubkeyBuilderBlock = (SubkeyBuilder.() -> Unit)

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
class OpenPgpKeyGenerator(private val policy: Policy = PGPainless.getPolicy()) {

    /**
     * Build a version 4 OpenPGP secret key.
     *
     * @param creationTime creation time for the secret key
     * @param preferences suite of algorithm preferences and enabled features
     */
    @JvmOverloads
    fun buildV4Key(
        creationTime: Date = Date(),
        preferences: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
    ): OpinionatedDefinePrimaryKeyV4 {
        return OpinionatedDefinePrimaryKeyV4(policy, creationTime, preferences)
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

    // Dedicated protector for the primary key.
    protected var primaryKeyProtector: SecretKeyRingProtector? = null

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
        block: PrimaryKeyBuilderBlock?
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
        block: PrimaryKeyBuilderBlock? = null
    ): O {
        require(type.canCertify) {
            "Primary key cannot use algorithm ${type.algorithm} because it needs to be " +
                "signing capable."
        }
        return doSetPrimaryKey(type, keyFlags, creationTime, block)
    }

    fun setPrimaryKey(type: KeyType, block: PrimaryKeyBuilderBlock?): O =
        setPrimaryKey(type, listOf(KeyFlag.CERTIFY_OTHER), this.creationTime, block)

    protected abstract fun doSetPrimaryKey(
        type: KeyType,
        keyFlags: List<KeyFlag>?,
        creationTime: Date,
        block: PrimaryKeyBuilderBlock?
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
     * Return a [OpenPgpKeyTemplates] object which provides factory methods for generating OpenPGP
     * keys from templates.
     *
     * @return templates
     */
    abstract fun fromTemplate(): OpenPgpKeyTemplates

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

        /**
         * Set a dedicated [Passphrase] for the primary key. This is useful, if each (sub-) key of
         * this OpenPGP key is intended to use a different passphrase.
         *
         * If you want to use a single passphrase for the whole OpenPGP key (primary key + subkeys)
         * it is advised to pass in the passphrase in the last builder step ([DefineSubkeys.build])
         * instead.
         *
         * @param passphrase passphrase to protect the primary key with
         */
        fun setPrimaryKeyPassphrase(passphrase: Passphrase) =
            setPrimaryKeyProtector(SecretKeyRingProtector.unlockAnyKeyWith(passphrase))

        /**
         * Set a dedicated [SecretKeyRingProtector] for the primary key. This is useful, if each
         * (sub-) key of this OpenPGP key is intended to use a different passphrase.
         *
         * If you want to use the same protection for the whole OpenPGP key (primary key + subkeys)
         * it is advised to pass in the protector in the last builder step ([DefineSubkeys.build])
         * instead.
         *
         * @param protector protector to protect the primary key with
         */
        fun setPrimaryKeyProtector(protector: SecretKeyRingProtector) {
            builder.primaryKeyProtector = protector
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
    internal val primaryKey: PGPKeyPair,
    internal val primaryKeyProtector: SecretKeyRingProtector?,
    internal val policy: Policy,
    internal val creationTime: Date,
    internal val subkeys: MutableList<PGPKeyPair> = mutableListOf(),
    internal val subkeyProtectors: MutableMap<OpenPgpFingerprint, SecretKeyRingProtector> =
        mutableMapOf(),
    internal val skipDefaultBindingSignatureFor: MutableList<OpenPgpFingerprint> = mutableListOf()
) {

    /**
     * Add a subkey to the OpenPGP key. If no explicit binding signature is set inside [block], the
     * key will be bound using a default binding signature containing the given [flags].
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
        block: SubkeyBuilderBlock? = null
    ): B =
        apply {
            sanitizeKeyFlags(type.algorithm, flags)
            sanitizeSubkeyCreationTime(creationTime, primaryKey)

            var subkey = generateSubkey(type, creationTime)

            // Default function block will only set appropriate key flags
            val defaultBlock: SubkeyBuilderBlock = {
                addBindingSignature(
                    SelfSignatureSubpackets.applyHashed { flags?.let { setKeyFlags(it) } },
                    bindingTime = creationTime)
            }
            // if no custom function block is given, simply set key flags
            val subkeyBlock = block ?: defaultBlock

            subkey = invokeOnSubkey(subkey, subkeyBlock)

            // If no binding signature was added yet, add a default binding sig using the default
            // block
            if (!skipDefaultBindingSignatureFor.contains(OpenPgpFingerprint.of(subkey))) {
                subkey = invokeOnSubkey(subkey, defaultBlock)
            }
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
    protected abstract fun invokeOnSubkey(subkey: PGPKeyPair, block: SubkeyBuilderBlock?): PGPKeyPair

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
     * Finish the key generation and return the OpenPGP [PGPSecretKeyRing]. The [protector] is used
     * as a catch-all to protect any keys where the user did not specify protection explicitly
     * otherwise.
     *
     * @param protector protector to protect the OpenPGP key's secret components with
     * @return finished [PGPSecretKeyRing]
     */
    abstract fun build(protector: SecretKeyRingProtector): PGPSecretKeyRing

    /**
     * Finish the key generation and return the OpenPGP [PGPSecretKeyRing] protected with the given
     * [passphrase]. The [passphrase] is used as a catch-all to protect any keys where the user did
     * not specify protection explicitly otherwise.
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
         * If this method is not explicitly called at least once while adding a subkey, the subkey
         * will be bound using a default binding signature. To prevent adding this default
         * signature, call [skipDefaultBindingSignatureFor].
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
            skipDefaultBindingSignature()
        }

        /**
         * Do not bind the key using a default binding signature, even if the user did not add an
         * explicit binding signature. This method is useful mostly for testing to generate keys
         * with unbound subkeys.
         */
        fun skipDefaultBindingSignature() {
            builder.skipDefaultBindingSignatureFor.add(OpenPgpFingerprint.of(subkey))
        }

        abstract fun doAddBindingSignature(
            subpacketsCallback: SelfSignatureSubpackets.Callback,
            hashAlgorithm: HashAlgorithm,
            bindingTime: Date
        )

        /**
         * Set a dedicated [Passphrase] for the subkey. This is useful, if each (sub-) key of this
         * OpenPGP key is intended to use a different passphrase.
         *
         * If you want to use a single passphrase for the whole OpenPGP key (primary key + subkeys)
         * it is advised to pass in the passphrase in the last builder step ([DefineSubkeys.build])
         * instead.
         *
         * @param passphrase passphrase to protect the subkey with
         */
        fun setSubkeyPassphrase(passphrase: Passphrase) =
            setSubkeyProtector(SecretKeyRingProtector.unlockAnyKeyWith(passphrase))

        /**
         * Set a dedicated [SecretKeyRingProtector] for the subkey. This is useful, if each (sub-)
         * key of this OpenPGP key is intended to use a different protection method.
         *
         * If you want to use the same protection for the whole OpenPGP key (primary key + subkeys)
         * it is advised to pass in the protector in the last builder step ([DefineSubkeys.build])
         * instead.
         *
         * @param protector protector to protect the subkey with
         */
        fun setSubkeyProtector(protector: SecretKeyRingProtector) {
            builder.subkeyProtectors[OpenPgpFingerprint.of(subkey)] = protector
        }
    }
}

/** Templates for OpenPGP key generation. */
interface OpenPgpKeyTemplates {

    companion object {

        /**
         * Templates for version 4 OpenPGP keys.
         *
         * @return templates
         */
        @JvmStatic fun v4() = OpenPgpV4KeyTemplates()
    }
}
