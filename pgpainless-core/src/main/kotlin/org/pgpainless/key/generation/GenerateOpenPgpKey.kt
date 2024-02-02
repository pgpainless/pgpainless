// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.io.IOException
import java.io.InputStream
import java.util.*
import org.bouncycastle.bcpg.attr.ImageAttribute
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.bouncycastle.util.io.Streams
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

/**
 * OpenPGP key builder. This implementation supersedes the old [KeyRingBuilder].
 *
 * @param policy algorithm policy, which is consulted to determine suitable algorithms
 * @param referenceTime reference time for key generation
 * @param preferences set of preferred algorithms and enabled features
 */
open class GenerateOpenPgpKey(
    private val policy: Policy,
    private val referenceTime: Date = Date(),
    private val preferences: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
) {

    /** Builder for OpenPGP secret keys. */
    abstract class OpenPgpKeyBuilder(
        protected val policy: Policy,
        protected val referenceTime: Date,
        protected val preferences: AlgorithmSuite
    ) {

        /** Make sure, that the chosen [KeyType] is allowed. */
        open fun sanitizePublicKeyAlgorithms(keyType: KeyType, policy: Policy) {
            verifyAlgorithmComplianceWithPolicy(keyType, policy)
        }

        /**
         * Make sure, that the chosen [KeyType] complies to the given [Policy] by comparing it to
         * the [Policy.PublicKeyAlgorithmPolicy].
         *
         * @throws IllegalArgumentException if [keyType] fails to be accepted by [policy]
         */
        private fun verifyAlgorithmComplianceWithPolicy(keyType: KeyType, policy: Policy) {
            val algorithm = keyType.algorithm
            val bitStrength = keyType.bitStrength
            require(policy.publicKeyAlgorithmPolicy.isAcceptable(algorithm, bitStrength)) {
                "Public key algorithm policy violation: $algorithm with bit strength $bitStrength is not acceptable."
            }
        }
    }

    /**
     * Build an OpenPGP v4 key. The result will be a key compliant to RFC4880, RFC6637.
     *
     * @param keyType type of the primary key
     * @param flags key flags for the primary key. Defaults to [KeyFlag.CERTIFY_OTHER].
     * @return [V4GenerateOpenPgpKey] which can be further modified, e.g. add subkeys, user-ids etc.
     */
    fun buildV4Key(
        keyType: KeyType,
        flags: List<KeyFlag>? = listOf(KeyFlag.CERTIFY_OTHER)
    ): V4GenerateOpenPgpKey =
        V4GenerateOpenPgpKey(keyType, flags, policy, referenceTime, preferences)

    /**
     * Builder for version 4 OpenPGP keys.
     *
     * @param primaryKeyType type of the primary key
     * @param primaryFlags list of key-flags for the primary key. Can be `null`.
     * @param policy algorithm policy
     * @param referenceTime reference time for key generation
     * @param preferences set of algorithm preferences and enabled features for the key
     */
    class V4GenerateOpenPgpKey
    internal constructor(
        primaryKeyType: KeyType,
        primaryFlags: List<KeyFlag>?,
        policy: Policy,
        referenceTime: Date,
        preferences: AlgorithmSuite
    ) : OpenPgpKeyBuilder(policy, referenceTime, preferences) {

        init {
            require(primaryKeyType.canCertify) {
                "KeyType $primaryKeyType MUST be certification capable."
            }
            sanitizePublicKeyAlgorithms(primaryKeyType, policy)
        }

        private val primaryKey =
            OpenPgpComponentKeyBuilder.V4PrimaryKeyBuilder(primaryKeyType, referenceTime, policy)
        private val subkeys = mutableListOf<OpenPgpComponentKeyBuilder.V4SubkeyBuilder>()

        private val preferencesCallback =
            SelfSignatureSubpackets.applyHashed {
                setPreferredSymmetricKeyAlgorithms(preferences.symmetricKeyAlgorithms)
                setPreferredHashAlgorithms(preferences.hashAlgorithms)
                setPreferredCompressionAlgorithms(preferences.compressionAlgorithms)
                setFeatures(*preferences.features.toTypedArray())
                primaryFlags?.let { setKeyFlags(*it.toTypedArray()) }
            }

        /**
         * Add a user-id to the key. The subpackets of the binding signature are prepopulated,
         * setting algorithm preferences and features. However, the subpackets can still be modified
         * using the provided [subpacketsCallback].
         *
         * @param userId user-id to add
         * @param subpacketsCallback callback to modify the user-id binding signatures subpackets.
         * @return this
         */
        fun addUserId(
            userId: CharSequence,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            primaryKey.userId(
                userId, subpacketsCallback = preferencesCallback.then(subpacketsCallback))
        }

        /**
         * Add a user-attribute to the key. The subpackets of the binding signature are
         * prepopulated, setting algorithm preferences and features. However, the subpackets can
         * still be modified using the provided [subpacketsCallback].
         *
         * @param attribute user-attribute to add
         * @param subpacketsCallback callback to modify the user-attribute binding signatures
         *   subpackets.
         * @return this
         */
        fun addUserAttribute(
            attribute: PGPUserAttributeSubpacketVector,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            primaryKey.userAttribute(
                attribute, subpacketsCallback = preferencesCallback.then(subpacketsCallback))
        }

        /**
         * Add the contents of a JPEG input stream as image attribute to the key.
         *
         * @param jpegInputStream input stream containing a JPEG image
         * @param subpacketsCallback callback to modify the user-attribute binding signature
         *   subpackets.
         * @return this
         */
        @Throws(IOException::class)
        fun addJpegImage(
            jpegInputStream: InputStream,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            PGPUserAttributeSubpacketVectorGenerator()
                .apply { setImageAttribute(ImageAttribute.JPEG, Streams.readAll(jpegInputStream)) }
                .generate()
                .let { addUserAttribute(it, subpacketsCallback) }
        }

        /**
         * Add a subkey to the key. The subpackets of the binding signature will be populated with
         * issuer information, the passed in [bindingTime] as signature creation time and given
         * key-flags (if non-null). You can further manipulate the subpackets by passing in an
         * appropriate [subpacketsCallback].
         *
         * @param keyType type of the key
         * @param creationTime creation time of the key. Defaults to [referenceTime]
         * @param bindingTime creation time of the binding signature. Defaults to [creationTime]
         * @param keyFlags list of key-flags for the subkey.
         * @param subpacketsCallback callback to modify the subpackets of the binding signature
         */
        fun addSubkey(
            keyType: KeyType,
            creationTime: Date = referenceTime,
            bindingTime: Date = creationTime,
            keyFlags: List<KeyFlag>? = null,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) =
            addSubkey(
                OpenPgpComponentKeyBuilder.V4SubkeyBuilder(
                    keyType, creationTime, policy, primaryKey),
                SelfSignatureSubpackets.applyHashed {
                        setSignatureCreationTime(bindingTime)
                        keyFlags?.let { setKeyFlags(it) }
                    }
                    .then(subpacketsCallback))

        fun addSubkey(
            subkeyBuilder: OpenPgpComponentKeyBuilder.V4SubkeyBuilder,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            sanitizePublicKeyAlgorithms(subkeyBuilder.type, policy)
            subkeys.add(subkeyBuilder.bindingSignature(subpacketsCallback = subpacketsCallback))
        }

        /**
         * Add a new subkey to be used for encryption. The binding signature will mark the key as
         * encryption-capable using both [KeyFlag.ENCRYPT_COMMS] and [KeyFlag.ENCRYPT_STORAGE].
         *
         * @param keyType type of the encryption subkey
         * @param creationTime time of creation of the subkey
         * @param bindingTime creation time of the binding signature
         * @return builder
         */
        fun addEncryptionSubkey(
            keyType: KeyType,
            creationTime: Date = referenceTime,
            bindingTime: Date = creationTime
        ) = apply {
            require(keyType.canEncryptCommunication || keyType.canEncryptStorage) {
                "KeyType $keyType cannot be used for encryption keys."
            }
            addSubkey(
                keyType,
                creationTime,
                bindingTime,
                listOf(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))
        }

        /**
         * Add a new subkey to be used for creating data signatures. The binding signature will mark
         * the key as signing-capable using [KeyFlag.SIGN_DATA].
         *
         * @param keyType type of the signing subkey
         * @param creationTime time of creation of the subkey
         * @param bindingTime creation time of the binding signature
         * @return builder
         */
        fun addSigningSubkey(
            keyType: KeyType,
            creationTime: Date = referenceTime,
            bindingTime: Date = creationTime
        ) = apply {
            require(keyType.canSign) { "KeyType $keyType cannot be used for signing keys." }
            addSubkey(keyType, creationTime, bindingTime, listOf(KeyFlag.SIGN_DATA))
        }

        /**
         * Build the finished OpenPGP key. By default, the key will not be protected using
         * passphrases. To set a passphrase, you can provide
         * [SecretKeyRingProtector.unlockAnyKeyWith] with a passphrase of your choice.
         *
         * @param protector protector to secure the secret keys using passphrases. Defaults to
         *   [SecretKeyRingProtector.unprotectedKeys].
         * @return OpenPGP Secret Key
         */
        fun build(
            protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
        ): PGPSecretKeyRing {

            // add a direct key sig with preferences
            primaryKey.directKeySignature(subpacketsCallback = preferencesCallback)

            return PGPSecretKeyRing(
                mutableListOf(
                        toSecretKey(primaryKey, true, protector.getEncryptor(primaryKey.key.keyID)))
                    .plus(
                        subkeys.map {
                            toSecretKey(it, false, protector.getEncryptor(it.key.keyID))
                        }))
        }

        /**
         * Convert a [OpenPgpComponentKeyBuilder.V4ComponentKeyBuilder] to a version 4
         * [PGPSecretKey].
         *
         * @param key builder
         * @param isPrimaryKey if true, the result will be a primary key, a subkey otherwise.
         * @param encryptor encryptor to protect the secret key. Can be null for unencrypted keys.
         */
        private fun toSecretKey(
            key: OpenPgpComponentKeyBuilder.V4ComponentKeyBuilder<*>,
            isPrimaryKey: Boolean,
            encryptor: PBESecretKeyEncryptor?
        ): PGPSecretKey {
            return PGPSecretKey(
                key.key.privateKey,
                key.key.publicKey,
                ImplementationFactory.getInstance().v4FingerprintCalculator,
                isPrimaryKey,
                encryptor)
        }
    }
}
