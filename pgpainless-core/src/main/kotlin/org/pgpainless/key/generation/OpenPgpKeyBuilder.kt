// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.util.*
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
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
open class OpenPgpKeyBuilder(
    protected val policy: Policy,
    protected val referenceTime: Date = Date(),
    protected val preferences: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
) {

    /**
     * Build an OpenPGP v4 key. The result will be a key compliant to RFC4880, RFC6637.
     *
     * @param keyType type of the primary key
     * @param flags key flags for the primary key. Defaults to [KeyFlag.CERTIFY_OTHER].
     * @return [V4OpenPgpKeyBuilder] which can be further modified, e.g. add subkeys, user-ids etc.
     */
    fun buildV4Key(
        keyType: KeyType,
        flags: List<KeyFlag>? = listOf(KeyFlag.CERTIFY_OTHER)
    ): V4OpenPgpKeyBuilder = V4OpenPgpKeyBuilder(keyType, flags, policy, referenceTime, preferences)

    /**
     * Builder for version 4 OpenPGP keys.
     *
     * @param primaryKeyType type of the primary key
     * @param primaryFlags list of key-flags for the primary key. Can be `null`.
     * @param policy algorithm policy
     * @param referenceTime reference time for key generation
     * @param preferences set of algorithm preferences and enabled features for the key
     */
    class V4OpenPgpKeyBuilder
    internal constructor(
        primaryKeyType: KeyType,
        primaryFlags: List<KeyFlag>?,
        policy: Policy,
        referenceTime: Date,
        preferences: AlgorithmSuite
    ) : OpenPgpKeyBuilder(policy, referenceTime, preferences) {

        private val primaryKey =
            BaseOpenPgpKeyBuilder.BaseV4PrimaryKeyBuilder(primaryKeyType, referenceTime, policy)
        private val subkeys = mutableListOf<BaseOpenPgpKeyBuilder.BaseV4SubkeyBuilder>()

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
                BaseOpenPgpKeyBuilder.BaseV4SubkeyBuilder(
                    keyType, creationTime, policy, primaryKey),
                SelfSignatureSubpackets.applyHashed {
                        setSignatureCreationTime(bindingTime)
                        keyFlags?.let { setKeyFlags(it) }
                    }
                    .then(subpacketsCallback))

        fun addSubkey(
            subkeyBuilder: BaseOpenPgpKeyBuilder.BaseV4SubkeyBuilder,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            subkeys.add(subkeyBuilder.bindingSignature(subpacketsCallback = subpacketsCallback))
        }

        fun addEncryptionSubkey(
            keyType: KeyType,
            creationTime: Date = referenceTime,
            bindingTime: Date = creationTime
        ) =
            addSubkey(
                keyType,
                creationTime,
                bindingTime,
                listOf(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))

        fun addSigningSubkey(
            keyType: KeyType,
            creationTime: Date = referenceTime,
            bindingTime: Date = creationTime
        ) = addSubkey(keyType, creationTime, bindingTime, listOf(KeyFlag.SIGN_DATA))

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

        private fun toSecretKey(
            key: BaseOpenPgpKeyBuilder.BaseV4KeyBuilder<*>,
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
