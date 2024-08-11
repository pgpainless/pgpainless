// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.io.IOException
import java.security.KeyPairGenerator
import java.util.*
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.util.Strings
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.bouncycastle.extensions.unlock
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.policy.Policy
import org.pgpainless.provider.ProviderFactory
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper
import org.pgpainless.util.Passphrase

class KeyRingBuilder : KeyRingBuilderInterface<KeyRingBuilder> {

    private var primaryKeySpec: KeySpec? = null
    private val subKeySpecs = mutableListOf<KeySpec>()
    private val userIds = mutableMapOf<String, SelfSignatureSubpackets.Callback?>()
    private var passphrase = Passphrase.emptyPassphrase()
    private var expirationDate: Date? = Date(System.currentTimeMillis() + (5 * MILLIS_IN_YEAR))

    override fun setPrimaryKey(keySpec: KeySpec): KeyRingBuilder = apply {
        verifyKeySpecCompliesToPolicy(keySpec, PGPainless.getPolicy())
        verifyPrimaryKeyCanCertify(keySpec)
        this.primaryKeySpec = keySpec
    }

    override fun addSubkey(keySpec: KeySpec): KeyRingBuilder = apply {
        verifyKeySpecCompliesToPolicy(keySpec, PGPainless.getPolicy())
        subKeySpecs.add(keySpec)
    }

    override fun addUserId(userId: CharSequence): KeyRingBuilder = apply {
        userIds[userId.toString().trim()] = null
    }

    override fun addUserId(userId: ByteArray): KeyRingBuilder =
        addUserId(Strings.fromUTF8ByteArray(userId))

    override fun setExpirationDate(expirationDate: Date?): KeyRingBuilder = apply {
        if (expirationDate == null) {
            this.expirationDate = null
            return@apply
        }
        this.expirationDate =
            expirationDate.let {
                require(Date() < expirationDate) { "Expiration date must be in the future." }
                expirationDate
            }
    }

    override fun setPassphrase(passphrase: Passphrase): KeyRingBuilder = apply {
        this.passphrase = passphrase
    }

    private fun verifyKeySpecCompliesToPolicy(keySpec: KeySpec, policy: Policy) {
        val algorithm = keySpec.keyType.algorithm
        val bitStrength = keySpec.keyType.bitStrength
        require(policy.publicKeyAlgorithmPolicy.isAcceptable(algorithm, bitStrength)) {
            "Public key algorithm policy violation: $algorithm with bit strength $bitStrength is not acceptable."
        }
    }

    private fun verifyPrimaryKeyCanCertify(spec: KeySpec) {
        require(keyIsCertificationCapable(spec)) {
            "Key algorithm ${spec.keyType.name} is not capable of creation certifications."
        }
    }

    private fun keyIsCertificationCapable(keySpec: KeySpec) = keySpec.keyType.canCertify

    override fun build(): PGPSecretKeyRing {
        val keyFingerprintCalculator = ImplementationFactory.getInstance().v4FingerprintCalculator
        val secretKeyEncryptor = buildSecretKeyEncryptor(keyFingerprintCalculator)
        val secretKeyDecryptor = buildSecretKeyDecryptor()

        passphrase.clear() // Passphrase was used above, so we can get rid of it

        // generate primary key
        requireNotNull(primaryKeySpec) { "Primary Key spec required." }
        val certKey = generateKeyPair(primaryKeySpec!!)
        val signer = buildContentSigner(certKey)
        val signatureGenerator = PGPSignatureGenerator(signer, certKey.publicKey)

        val hashedSubPacketGenerator = primaryKeySpec!!.subpacketGenerator
        hashedSubPacketGenerator.setIssuer(certKey.publicKey)
        expirationDate?.let { hashedSubPacketGenerator.setKeyExpirationTime(certKey.publicKey, it) }
        if (userIds.isNotEmpty()) {
            hashedSubPacketGenerator.setPrimaryUserId()
        }

        val generator = PGPSignatureSubpacketGenerator()
        SignatureSubpacketsHelper.applyTo(hashedSubPacketGenerator, generator)
        val hashedSubPackets = generator.generate()
        val ringGenerator =
            if (userIds.isEmpty()) {
                PGPKeyRingGenerator(
                    certKey,
                    keyFingerprintCalculator,
                    hashedSubPackets,
                    null,
                    signer,
                    secretKeyEncryptor)
            } else {
                userIds.keys.first().let { primaryUserId ->
                    PGPKeyRingGenerator(
                        SignatureType.POSITIVE_CERTIFICATION.code,
                        certKey,
                        primaryUserId,
                        keyFingerprintCalculator,
                        hashedSubPackets,
                        null,
                        signer,
                        secretKeyEncryptor)
                }
            }

        addSubKeys(certKey, ringGenerator)

        // Generate secret key ring with only primary userId
        val secretKeyRing = ringGenerator.generateSecretKeyRing()
        val secretKeys = secretKeyRing.secretKeys

        // Attempt to add additional user-ids to the primary public key
        var primaryPubKey = secretKeys.next().publicKey
        val privateKey = secretKeyRing.secretKey.unlock(secretKeyDecryptor)
        val userIdIterator = userIds.entries.iterator()
        if (userIdIterator.hasNext()) {
            userIdIterator.next() // Skip primary userId
        }
        while (userIdIterator.hasNext()) {
            val additionalUserId = userIdIterator.next()
            val userIdString = additionalUserId.key
            val callback = additionalUserId.value
            val subpackets =
                if (callback == null) {
                    hashedSubPacketGenerator.also { it.setPrimaryUserId(null) }
                } else {
                    SignatureSubpackets.createHashedSubpackets(primaryPubKey).also {
                        callback.modifyHashedSubpackets(it)
                    }
                }
            signatureGenerator.init(SignatureType.POSITIVE_CERTIFICATION.code, privateKey)
            signatureGenerator.setHashedSubpackets(SignatureSubpacketsHelper.toVector(subpackets))
            val additionalUserIdSignature =
                signatureGenerator.generateCertification(userIdString, primaryPubKey)
            primaryPubKey =
                PGPPublicKey.addCertification(
                    primaryPubKey, userIdString, additionalUserIdSignature)
        }

        // Reassemble secret key ring with modified primary key
        val primarySecretKey =
            PGPSecretKey(
                privateKey, primaryPubKey, keyFingerprintCalculator, true, secretKeyEncryptor)
        val secretKeyList = mutableListOf(primarySecretKey)
        while (secretKeys.hasNext()) {
            secretKeyList.add(secretKeys.next())
        }
        return PGPSecretKeyRing(secretKeyList)
    }

    private fun addSubKeys(primaryKey: PGPKeyPair, ringGenerator: PGPKeyRingGenerator) {
        for (subKeySpec in subKeySpecs) {
            val subKey = generateKeyPair(subKeySpec)
            if (subKeySpec.isInheritedSubPackets) {
                ringGenerator.addSubKey(subKey)
            } else {
                var hashedSubpackets = subKeySpec.subpackets
                try {
                    hashedSubpackets =
                        addPrimaryKeyBindingSignatureIfNecessary(
                            primaryKey, subKey, hashedSubpackets)
                } catch (e: IOException) {
                    throw PGPException(
                        "Exception while adding primary key binding signature to signing subkey.",
                        e)
                }
                ringGenerator.addSubKey(subKey, hashedSubpackets, null)
            }
        }
    }

    private fun addPrimaryKeyBindingSignatureIfNecessary(
        primaryKey: PGPKeyPair,
        subKey: PGPKeyPair,
        hashedSubpackets: PGPSignatureSubpacketVector
    ): PGPSignatureSubpacketVector {
        val keyFlagMask = hashedSubpackets.keyFlags
        if (!KeyFlag.hasKeyFlag(keyFlagMask, KeyFlag.SIGN_DATA) &&
            !KeyFlag.hasKeyFlag(keyFlagMask, KeyFlag.CERTIFY_OTHER)) {
            return hashedSubpackets
        }

        val bindingSignatureGenerator =
            PGPSignatureGenerator(buildContentSigner(subKey), subKey.publicKey)
        bindingSignatureGenerator.init(SignatureType.PRIMARYKEY_BINDING.code, subKey.privateKey)
        val primaryKeyBindingSig =
            bindingSignatureGenerator.generateCertification(primaryKey.publicKey, subKey.publicKey)
        val subpacketGenerator = PGPSignatureSubpacketGenerator(hashedSubpackets)
        subpacketGenerator.addEmbeddedSignature(false, primaryKeyBindingSig)
        return subpacketGenerator.generate()
    }

    private fun buildContentSigner(certKey: PGPKeyPair): PGPContentSignerBuilder {
        val hashAlgorithm =
            PGPainless.getPolicy().certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm
        return ImplementationFactory.getInstance()
            .getPGPContentSignerBuilder(certKey.publicKey.algorithm, hashAlgorithm.algorithmId)
    }

    private fun buildSecretKeyEncryptor(
        keyFingerprintCalculator: PGPDigestCalculator
    ): PBESecretKeyEncryptor? {
        val keyEncryptionAlgorithm =
            PGPainless.getPolicy()
                .symmetricKeyEncryptionAlgorithmPolicy
                .defaultSymmetricKeyAlgorithm
        check(passphrase.isValid) { "Passphrase was cleared." }
        return if (passphrase.isEmpty) null
        else
            ImplementationFactory.getInstance()
                .getPBESecretKeyEncryptor(
                    keyEncryptionAlgorithm, keyFingerprintCalculator, passphrase)
    }

    private fun buildSecretKeyDecryptor(): PBESecretKeyDecryptor? {
        check(passphrase.isValid) { "Passphrase was cleared." }
        return if (passphrase.isEmpty) null
        else ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase)
    }

    companion object {
        const val MILLIS_IN_YEAR = 1000L * 60 * 60 * 24 * 365

        @JvmStatic
        @JvmOverloads
        fun generateKeyPair(
            spec: KeySpec,
            creationTime: Date = spec.keyCreationDate ?: Date()
        ): PGPKeyPair {
            spec.keyType.let { type ->
                // Create raw Key Pair
                val keyPair =
                    KeyPairGenerator.getInstance(type.name, ProviderFactory.provider)
                        .also { it.initialize(type.algorithmSpec) }
                        .generateKeyPair()

                // Form PGP Key Pair
                return ImplementationFactory.getInstance()
                    .getPGPKeyPair(type.algorithm, keyPair, creationTime)
            }
        }
    }
}
