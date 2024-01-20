package org.pgpainless.key.generation

import java.util.*
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

class OpenPgpV4KeyGenerator(
    keyType: KeyType,
    private val policy: Policy,
    private val referenceTime: Date = Date(),
    private val keyGenerationPolicy: AlgorithmSuite = policy.keyGenerationAlgorithmSuite
) {

    private val primaryKey = OpenPgpKeyBuilder.V4PrimaryKeyBuilder(keyType, referenceTime, policy)
    private val subkeys = mutableListOf<OpenPgpKeyBuilder.V4SubkeyBuilder>()

    fun addUserId(
        userId: CharSequence,
        subpacketsCallback: SelfSignatureSubpackets.Callback =
            SelfSignatureSubpackets.defaultCallback()
    ) = apply { primaryKey.userId(userId, subpacketsCallback = subpacketsCallback) }

    fun addUserAttribute(
        attribute: PGPUserAttributeSubpacketVector,
        subpacketsCallback: SelfSignatureSubpackets.Callback =
            SelfSignatureSubpackets.defaultCallback()
    ) = apply {
        primaryKey.userAttribute(attribute, subpacketsCallback = subpacketsCallback)
    }

    fun addSubkey(
        keyType: KeyType,
        creationTime: Date = referenceTime,
        bindingTime: Date = creationTime
    ) =
        addSubkey(
            OpenPgpKeyBuilder.V4SubkeyBuilder(keyType, creationTime, policy, primaryKey),
            bindingTime)

    fun addSubkey(
        subkeyBuilder: OpenPgpKeyBuilder.V4SubkeyBuilder,
        bindingTime: Date = subkeyBuilder.creationTime
    ) = apply { subkeys.add(subkeyBuilder) }

    fun addEncryptionSubkey(
        keyType: KeyType,
        creationTime: Date = referenceTime,
        bindingTime: Date = creationTime
    ) =
        addSubkey(
            OpenPgpKeyBuilder.V4SubkeyBuilder(keyType, creationTime, policy, primaryKey)
                .bindingSignature(
                    subpacketsCallback =
                        object : SelfSignatureSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: SelfSignatureSubpackets
                            ) {
                                hashedSubpackets.setSignatureCreationTime(bindingTime)
                                hashedSubpackets.setKeyFlags(
                                    KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
                            }
                        }))

    fun addSigningSubkey(
        keyType: KeyType,
        creationTime: Date = referenceTime,
        bindingTime: Date = creationTime
    ) =
        addSubkey(
            OpenPgpKeyBuilder.V4SubkeyBuilder(keyType, creationTime, policy, primaryKey)
                .bindingSignature(
                    subpacketsCallback =
                        object : SelfSignatureSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: SelfSignatureSubpackets
                            ) {
                                hashedSubpackets.setSignatureCreationTime(bindingTime)
                                hashedSubpackets.setKeyFlags(KeyFlag.SIGN_DATA)
                            }
                        }))

    fun build(protector: SecretKeyRingProtector): PGPSecretKeyRing {
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
}
