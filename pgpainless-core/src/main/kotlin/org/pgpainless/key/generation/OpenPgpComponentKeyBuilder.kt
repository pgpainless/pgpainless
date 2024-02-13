// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.security.KeyPairGenerator
import java.util.*
import org.pgpainless.bouncycastle.extensions.toPrimaryKeyFormat
import org.pgpainless.bouncycastle.extensions.toSubkeyFormat
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.algorithm.AlgorithmSuite
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

class OpenPgpComponentKeyBuilder {

    abstract class V4ComponentKeyBuilder<T : V4ComponentKeyBuilder<T>>(
        val type: KeyType,
        val creationTime: Date,
        val certificateCreationTime: Date = Date(),
        val policy: Policy
    ) {

        internal var pair = generateKeyPair()

        fun subkey(type: KeyType, creationTime: Date = certificateCreationTime): V4SubkeyBuilder =
            V4SubkeyBuilder(type, creationTime, policy, primaryKey())

        internal abstract fun primaryKey(): V4PrimaryKeyBuilder

        // Note: The result is a *primary* key pair, so subkeys need adjustment (toPrimaryOrSubkey)
        private fun generateKeyPair(): PGPKeyPair {
            // Create raw Key Pair
            val keyPair =
                KeyPairGenerator.getInstance(type.name, ProviderFactory.provider)
                    .also { it.initialize(type.algorithmSpec) }
                    .generateKeyPair()

            // Form PGP Key Pair
            return ImplementationFactory.getInstance()
                .getPGPV4KeyPair(type.algorithm, keyPair, creationTime)
                .let { toPrimaryOrSubkey(it) }
        }

        /**
         * Make sure, the PGP key packet is a subkey packet for subkeys, and a primary key packet
         * for primary keys.
         */
        protected abstract fun toPrimaryOrSubkey(keyPair: PGPKeyPair): PGPKeyPair
    }

    class V4PrimaryKeyBuilder(type: KeyType, creationTime: Date, policy: Policy) :
        V4ComponentKeyBuilder<V4PrimaryKeyBuilder>(type, creationTime, policy = policy) {

        fun userId(
            userId: CharSequence,
            certificationType: CertificationType = CertificationType.POSITIVE,
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            val sig =
                buildCertificationFor(
                    userId, certificationType, bindingTime, hashAlgorithm, subpacketsCallback)
            pair =
                PGPKeyPair(
                    PGPPublicKey.addCertification(pair.publicKey, userId.toString(), sig),
                    pair.privateKey)
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
                    pair.privateKey, pair.publicKey, certificationType.signatureType, hashAlgorithm)
            builder.hashedSubpackets.apply { setSignatureCreationTime(bindingTime) }
            builder.applyCallback(subpacketsCallback)
            return builder.build(userId)
        }

        fun userAttribute(
            userAttribute: PGPUserAttributeSubpacketVector,
            certificationType: CertificationType = CertificationType.POSITIVE,
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            val sig =
                buildCertificationFor(
                    userAttribute,
                    certificationType,
                    bindingTime,
                    hashAlgorithm,
                    subpacketsCallback)
            pair =
                PGPKeyPair(
                    PGPPublicKey.addCertification(pair.publicKey, userAttribute, sig),
                    pair.privateKey)
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
                    pair.privateKey, pair.publicKey, certificationType.signatureType, hashAlgorithm)
            builder.hashedSubpackets.apply { setSignatureCreationTime(bindingTime) }
            builder.applyCallback(subpacketsCallback)
            return builder.build(userAttribute)
        }

        fun directKeySignature(
            bindingTime: Date = creationTime,
            algorithmSuite: AlgorithmSuite = policy.keyGenerationAlgorithmSuite,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm(),
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            val sig =
                buildDirectKeySignature(
                    bindingTime, algorithmSuite, hashAlgorithm, subpacketsCallback)
            pair = PGPKeyPair(PGPPublicKey.addCertification(pair.publicKey, sig), pair.privateKey)
        }

        fun buildDirectKeySignature(
            bindingTime: Date,
            algorithmSuite: AlgorithmSuite,
            hashAlgorithm: HashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback
        ): PGPSignature {
            val builder =
                DirectKeySelfSignatureBuilder(pair.privateKey, pair.publicKey, hashAlgorithm)

            builder.hashedSubpackets.apply {
                setSignatureCreationTime(bindingTime)
                setPreferredHashAlgorithms(algorithmSuite.hashAlgorithms)
                setPreferredSymmetricKeyAlgorithms(algorithmSuite.symmetricKeyAlgorithms)
                setPreferredCompressionAlgorithms(algorithmSuite.compressionAlgorithms)
            }

            builder.applyCallback(subpacketsCallback)

            return builder.build()
        }

        override fun toPrimaryOrSubkey(keyPair: PGPKeyPair) = keyPair.toPrimaryKeyFormat()

        override fun primaryKey() = this
    }

    class V4SubkeyBuilder(
        type: KeyType,
        creationTime: Date,
        policy: Policy,
        private val primaryKeyBuilder: V4PrimaryKeyBuilder
    ) : V4ComponentKeyBuilder<V4SubkeyBuilder>(type, creationTime, policy = policy) {

        fun bindingSignature(
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ) = apply {
            val sig = buildBindingSignature(bindingTime, hashAlgorithm, subpacketsCallback)
            pair = PGPKeyPair(PGPPublicKey.addCertification(pair.publicKey, sig), pair.privateKey)
        }

        fun buildBindingSignature(
            bindingTime: Date = creationTime,
            hashAlgorithm: HashAlgorithm =
                policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm,
            subpacketsCallback: SelfSignatureSubpackets.Callback = SelfSignatureSubpackets.nop()
        ): PGPSignature {
            val builder =
                SubkeyBindingSignatureBuilder(
                    primaryKeyBuilder.pair.privateKey,
                    primaryKeyBuilder.pair.publicKey,
                    hashAlgorithm)

            builder.hashedSubpackets.setSignatureCreationTime(bindingTime)
            builder.applyCallback(subpacketsCallback)

            // For signing-keys: Add backsig
            if (builder.hashedSubpackets.getKeyFlags().orEmpty().contains(KeyFlag.SIGN_DATA) &&
                builder.hashedSubpackets.getEmbeddedSignaturePackets().isEmpty()) {

                // Create back-sig
                val backSigBuilder =
                    PrimaryKeyBindingSignatureBuilder(
                        pair.privateKey, pair.publicKey, hashAlgorithm)

                backSigBuilder.hashedSubpackets.setSignatureCreationTime(bindingTime)

                val backSig = backSigBuilder.build(primaryKey().pair.publicKey)
                builder.hashedSubpackets.addEmbeddedSignature(backSig)
            }

            return builder.build(pair.publicKey)
        }

        override fun toPrimaryOrSubkey(keyPair: PGPKeyPair) = keyPair.toSubkeyFormat()

        override fun primaryKey() = primaryKeyBuilder.primaryKey()
    }
}
