package org.pgpainless.key.generation

import org.bouncycastle.bcpg.PublicSubkeyPacket
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.provider.ProviderFactory
import org.pgpainless.signature.builder.SelfSignatureBuilder
import org.pgpainless.signature.builder.SubkeyBindingSignatureBuilder
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import java.security.KeyPairGenerator
import java.util.*

class OpenPgpKeyBuilder {

    fun buildV4Key(
        type: KeyType,
        creationTime: Date = Date()
    ): V4PrimaryKeyBuilder = V4PrimaryKeyBuilder(type, creationTime)

    abstract class V4KeyBuilder<T: V4KeyBuilder<T>>(
        val type: KeyType,
        val creationTime: Date,
        val certificateCreationTime: Date = Date()
    ) {

        internal var key = generateKeyPair()

        fun subkey(
            type: KeyType,
            creationTime: Date = certificateCreationTime
        ): V4SubkeyBuilder = V4SubkeyBuilder(type, creationTime, primaryKey())

        internal abstract fun primaryKey(): V4PrimaryKeyBuilder

        private fun generateKeyPair(): PGPKeyPair {
            // Create raw Key Pair
            val keyPair = KeyPairGenerator.getInstance(type.name, ProviderFactory.provider)
                .also { it.initialize(type.algorithmSpec) }
                .generateKeyPair()

            // Form PGP Key Pair
            return ImplementationFactory.getInstance()
                .getPGPV4KeyPair(type.algorithm, keyPair, creationTime)
                .let {
                    adjustKeyPacket(it)
                }
        }

        protected abstract fun adjustKeyPacket(keyPair: PGPKeyPair): PGPKeyPair
    }

    class V4PrimaryKeyBuilder(
        type: KeyType,
        creationTime: Date
    ): V4KeyBuilder<V4PrimaryKeyBuilder>(type, creationTime) {

        fun userId(
            userId: CharSequence,
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA512,
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                object : SelfSignatureSubpackets.Callback {

                }
        ) = apply {
            val sig = SelfSignatureBuilder(
                key.privateKey,
                key.publicKey,
                SignatureType.POSITIVE_CERTIFICATION,
                hashAlgorithm)
                .applyCallback(subpacketsCallback)
                .build(userId)
            key = PGPKeyPair(
                PGPPublicKey.addCertification(key.publicKey, userId.toString(), sig),
                key.privateKey
            )
        }

        override fun adjustKeyPacket(keyPair: PGPKeyPair): PGPKeyPair {
            return keyPair // is already a secret key packet
        }

        override fun primaryKey() = this
    }

    class V4SubkeyBuilder(
        type: KeyType,
        creationTime: Date,
        private val primaryKeyBuilder: V4PrimaryKeyBuilder
    ): V4KeyBuilder<V4SubkeyBuilder>(type, creationTime) {

        fun bindingSignature(subpacketCallback: SelfSignatureSubpackets.Callback) = apply {
            SubkeyBindingSignatureBuilder(primaryKeyBuilder.key.privateKey, primaryKeyBuilder.key.publicKey)
                .applyCallback(subpacketCallback)
                .build(key.publicKey)
                .let {
                    key = PGPKeyPair(
                        PGPPublicKey.addCertification(key.publicKey, it),
                        key.privateKey)
                }
        }

        override fun adjustKeyPacket(keyPair: PGPKeyPair): PGPKeyPair {
            val fpCalc = ImplementationFactory.getInstance().keyFingerprintCalculator
            val pubkey = keyPair.publicKey
            val privkey = keyPair.privateKey
            // form subkey packet
            val subkey = PublicSubkeyPacket(pubkey.algorithm,
                pubkey.creationTime, pubkey.publicKeyPacket.key)
            return PGPKeyPair(
                PGPPublicKey(subkey, fpCalc),
                PGPPrivateKey(pubkey.keyID, subkey, privkey.privateKeyDataPacket)
            )
        }

        override fun primaryKey() = primaryKeyBuilder.primaryKey()

        fun bindingSignature(
            bindingTime: Date = creationTime
        ): V4SubkeyBuilder = bindingSignature(object : SelfSignatureSubpackets.Callback {
            override fun modifyHashedSubpackets(hashedSubpackets: SelfSignatureSubpackets) {
                hashedSubpackets.setSignatureCreationTime(bindingTime)
            }
        })
    }
}
