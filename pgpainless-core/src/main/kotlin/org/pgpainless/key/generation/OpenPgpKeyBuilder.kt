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

open class OpenPgpKeyBuilder(
    protected val policy: Policy,
    protected val referenceTime: Date = Date(),
    protected val keyGenerationPolicy: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
) {

    fun buildV4Key(
        keyType: KeyType,
    ): V4OpenPgpKeyBuilder =
        V4OpenPgpKeyBuilder(keyType, policy, referenceTime, keyGenerationPolicy)

    class V4OpenPgpKeyBuilder(
        keyType: KeyType,
        policy: Policy,
        referenceTime: Date,
        keyGenerationPolicy: AlgorithmSuite
    ) : OpenPgpKeyBuilder(policy, referenceTime, keyGenerationPolicy) {

        private val primaryKey =
            BaseOpenPgpKeyBuilder.BaseV4PrimaryKeyBuilder(keyType, referenceTime, policy)

        private val subkeys = mutableListOf<BaseOpenPgpKeyBuilder.BaseV4SubkeyBuilder>()

        fun addUserId(
            userId: CharSequence,
            algorithmSuite: AlgorithmSuite = keyGenerationPolicy,
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                SelfSignatureSubpackets.defaultCallback()
        ) = apply { primaryKey.userId(userId, algorithmSuite, subpacketsCallback = subpacketsCallback) }

        fun addUserAttribute(
            attribute: PGPUserAttributeSubpacketVector,
            algorithmSuite: AlgorithmSuite = keyGenerationPolicy,
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                SelfSignatureSubpackets.defaultCallback()
        ) = apply { primaryKey.userAttribute(attribute, algorithmSuite, subpacketsCallback = subpacketsCallback) }

        fun addSubkey(
            keyType: KeyType,
            creationTime: Date = referenceTime,
            bindingTime: Date = creationTime,
            keyFlags: List<KeyFlag>?
        ) =
            addSubkey(
                BaseOpenPgpKeyBuilder.BaseV4SubkeyBuilder(
                    keyType, creationTime, policy, primaryKey),
                bindingTime,
                keyFlags)

        fun addSubkey(
            subkeyBuilder: BaseOpenPgpKeyBuilder.BaseV4SubkeyBuilder,
            bindingTime: Date = subkeyBuilder.creationTime,
            keyFlags: List<KeyFlag>?
        ) = apply {
            subkeys.add(
                subkeyBuilder.also {
                    it.bindingSignature(
                        bindingTime,
                        subpacketsCallback =
                            object : SelfSignatureSubpackets.Callback {
                                override fun modifyHashedSubpackets(
                                    hashedSubpackets: SelfSignatureSubpackets
                                ) {
                                    hashedSubpackets.setSignatureCreationTime(bindingTime)
                                    keyFlags?.let { flagList ->
                                        hashedSubpackets.setKeyFlags(flagList)
                                    }
                                }
                            })
                })
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
            return PGPSecretKeyRing(
                mutableListOf(
                        PGPSecretKey(
                            primaryKey.key.privateKey,
                            primaryKey.key.publicKey,
                            ImplementationFactory.getInstance().v4FingerprintCalculator,
                            true,
                            protector.getEncryptor(primaryKey.key.keyID)))
                    .plus(
                        subkeys.map {
                            PGPSecretKey(
                                it.key.privateKey,
                                it.key.publicKey,
                                ImplementationFactory.getInstance().v4FingerprintCalculator,
                                false,
                                protector.getEncryptor(it.key.keyID))
                        }))
        }

        private fun defaultPrimarySubpacketsCallback(): SelfSignatureSubpackets.Callback =
            object : SelfSignatureSubpackets.Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                    hashedSubpackets.apply {
                        setPreferredHashAlgorithms(keyGenerationPolicy.hashAlgorithms)
                        setPreferredSymmetricKeyAlgorithms(keyGenerationPolicy.symmetricKeyAlgorithms)
                        setPreferredCompressionAlgorithms(keyGenerationPolicy.compressionAlgorithms)
                        setKeyFlags(KeyFlag.CERTIFY_OTHER)
                    }
                }
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
