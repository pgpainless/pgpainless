package org.pgpainless.key.generation

import java.security.KeyPairGenerator
import java.util.*
import org.bouncycastle.bcpg.PublicSubkeyPacket
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.algorithm.CertificationType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.policy.Policy
import org.pgpainless.provider.ProviderFactory
import org.pgpainless.signature.builder.DirectKeySelfSignatureBuilder
import org.pgpainless.signature.builder.PrimaryKeyBindingSignatureBuilder
import org.pgpainless.signature.builder.SelfSignatureBuilder
import org.pgpainless.signature.builder.SubkeyBindingSignatureBuilder
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

class OpenPgpKeyBuilder {

    fun buildV4Key(
        type: KeyType,
        creationTime: Date = Date(),
        policy: Policy
    ): V4PrimaryKeyBuilder = V4PrimaryKeyBuilder(type, creationTime, policy)

    abstract class V4KeyBuilder<T : V4KeyBuilder<T>>(
        val type: KeyType,
        val creationTime: Date,
        val certificateCreationTime: Date = Date(),
        val policy: Policy
    ) {

        internal var key = generateKeyPair()

        fun subkey(type: KeyType, creationTime: Date = certificateCreationTime): V4SubkeyBuilder =
            V4SubkeyBuilder(type, creationTime, policy, primaryKey())

        internal abstract fun primaryKey(): V4PrimaryKeyBuilder

        private fun generateKeyPair(): PGPKeyPair {
            // Create raw Key Pair
            val keyPair =
                KeyPairGenerator.getInstance(type.name, ProviderFactory.provider)
                    .also { it.initialize(type.algorithmSpec) }
                    .generateKeyPair()

            // Form PGP Key Pair
            return ImplementationFactory.getInstance()
                .getPGPV4KeyPair(type.algorithm, keyPair, creationTime)
                .let { adjustKeyPacket(it) }
        }

        /**
         * Make sure, the PGP key packet is a subkey packet for subkeys, and a primary key packet
         * for primary keys.
         */
        protected abstract fun adjustKeyPacket(keyPair: PGPKeyPair): PGPKeyPair
    }

    class V4PrimaryKeyBuilder(type: KeyType, creationTime: Date, policy: Policy) :
        V4KeyBuilder<V4PrimaryKeyBuilder>(type, creationTime, policy = policy) {

        fun userId(
            userId: CharSequence,
            certificationType: CertificationType = CertificationType.POSITIVE,
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                SelfSignatureSubpackets.defaultCallback()
        ) = apply {
            val sig =
                buildCertificationFor(
                    userId, certificationType, bindingTime, hashAlgorithm, subpacketsCallback)
            key =
                PGPKeyPair(
                    PGPPublicKey.addCertification(key.publicKey, userId.toString(), sig),
                    key.privateKey)
        }

        fun buildCertificationFor(
            userId: CharSequence,
            certificationType: CertificationType,
            bindingTime: Date,
            hashAlgorithm: HashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            val builder =
                SelfSignatureBuilder(
                    key.privateKey, key.publicKey, certificationType.signatureType, hashAlgorithm)
            builder.hashedSubpackets.setSignatureCreationTime(bindingTime)
            builder.applyCallback(subpacketsCallback)
            return builder.build(userId)
        }

        fun userAttribute(
            userAttribute: PGPUserAttributeSubpacketVector,
            certificationType: CertificationType = CertificationType.POSITIVE,
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                SelfSignatureSubpackets.defaultCallback()
        ) = apply {
            val sig =
                buildCertificationFor(
                    userAttribute,
                    certificationType,
                    bindingTime,
                    hashAlgorithm,
                    subpacketsCallback)
            key =
                PGPKeyPair(
                    PGPPublicKey.addCertification(key.publicKey, userAttribute, sig),
                    key.privateKey)
        }

        fun buildCertificationFor(
            userAttribute: PGPUserAttributeSubpacketVector,
            certificationType: CertificationType,
            bindingTime: Date,
            hashAlgorithm: HashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            val builder =
                SelfSignatureBuilder(
                    key.privateKey, key.publicKey, certificationType.signatureType, hashAlgorithm)
            builder.hashedSubpackets.setSignatureCreationTime(bindingTime)
            builder.applyCallback(subpacketsCallback)
            return builder.build(userAttribute)
        }

        fun directKeySignature(
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm(),
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                SelfSignatureSubpackets.defaultCallback()
        ) = apply {
            val sig = buildDirectKeySignature(bindingTime, hashAlgorithm, subpacketsCallback)
            key = PGPKeyPair(PGPPublicKey.addCertification(key.publicKey, sig), key.privateKey)
        }

        fun buildDirectKeySignature(
            bindingTime: Date,
            hashAlgorithm: HashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            val builder =
                DirectKeySelfSignatureBuilder(key.privateKey, key.publicKey, hashAlgorithm)

            builder.hashedSubpackets.setSignatureCreationTime(bindingTime)
            builder.applyCallback(subpacketsCallback)

            return builder.build()
        }

        override fun adjustKeyPacket(keyPair: PGPKeyPair): PGPKeyPair {
            return keyPair // is already a secret key packet
        }

        override fun primaryKey() = this
    }

    class V4SubkeyBuilder(
        type: KeyType,
        creationTime: Date,
        policy: Policy,
        private val primaryKeyBuilder: V4PrimaryKeyBuilder
    ) : V4KeyBuilder<V4SubkeyBuilder>(type, creationTime, policy = policy) {

        fun bindingSignature(
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                SelfSignatureSubpackets.defaultCallback()
        ) = apply {
            val sig = buildBindingSignature(bindingTime, hashAlgorithm, subpacketsCallback)
            key = PGPKeyPair(PGPPublicKey.addCertification(key.publicKey, sig), key.privateKey)
        }

        fun buildBindingSignature(
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback =
                SelfSignatureSubpackets.defaultCallback()
        ): PGPSignature {
            val builder =
                SubkeyBindingSignatureBuilder(
                    primaryKeyBuilder.key.privateKey,
                    primaryKeyBuilder.key.publicKey,
                    hashAlgorithm)

            builder.hashedSubpackets.setSignatureCreationTime(bindingTime)
            builder.applyCallback(subpacketsCallback)

            if (builder.hashedSubpackets.getKeyFlags().orEmpty().contains(KeyFlag.SIGN_DATA) &&
                builder.hashedSubpackets.getEmbeddedSignaturePackets().isEmpty()) {

                // Create back-sig
                val backSigBuilder =
                    PrimaryKeyBindingSignatureBuilder(key.privateKey, key.publicKey, hashAlgorithm)

                backSigBuilder.hashedSubpackets.setSignatureCreationTime(bindingTime)

                val backSig = backSigBuilder.build(primaryKey().key.publicKey)
                builder.hashedSubpackets.addEmbeddedSignature(backSig)
            }

            return builder.build(key.publicKey)
        }

        override fun adjustKeyPacket(keyPair: PGPKeyPair): PGPKeyPair {
            val fpCalc = ImplementationFactory.getInstance().keyFingerprintCalculator
            val pubkey = keyPair.publicKey
            val privkey = keyPair.privateKey
            // form subkey packet
            val subkey =
                PublicSubkeyPacket(
                    pubkey.algorithm, pubkey.creationTime, pubkey.publicKeyPacket.key)
            return PGPKeyPair(
                PGPPublicKey(subkey, fpCalc),
                PGPPrivateKey(pubkey.keyID, subkey, privkey.privateKeyDataPacket))
        }

        override fun primaryKey() = primaryKeyBuilder.primaryKey()
    }
}
