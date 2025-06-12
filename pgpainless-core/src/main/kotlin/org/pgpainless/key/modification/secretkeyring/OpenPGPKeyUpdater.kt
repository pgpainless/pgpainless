// SPDX-FileCopyrightText: 2025 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring

import java.util.*
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites.Combination
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyEditor
import org.bouncycastle.openpgp.api.SignatureParameters
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.Feature
import org.pgpainless.bouncycastle.PolicyAdapter
import org.pgpainless.bouncycastle.extensions.getKeyVersion
import org.pgpainless.bouncycastle.extensions.toAEADCipherModes
import org.pgpainless.bouncycastle.extensions.toCompressionAlgorithms
import org.pgpainless.bouncycastle.extensions.toHashAlgorithms
import org.pgpainless.bouncycastle.extensions.toSymmetricKeyAlgorithms
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy

class OpenPGPKeyUpdater(
    private var key: OpenPGPKey,
    private val protector: SecretKeyRingProtector,
    private val api: PGPainless = PGPainless.getInstance(),
    private val policy: Policy = api.algorithmPolicy,
    private val referenceTime: Date = Date()
) {

    init {
        key =
            OpenPGPKey(
                key.pgpSecretKeyRing, api.implementation, PolicyAdapter(Policy.wildcardPolicy()))
    }

    private val keyEditor = OpenPGPKeyEditor(key, protector)

    fun extendExpirationIfExpiresBefore(
        expiresBeforeSeconds: Long,
        newExpirationTimeSecondsFromNow: Long? = _5YEARS
    ) = apply {
        require(expiresBeforeSeconds > 0) {
            "Time period to check expiration within MUST be positive."
        }
        require(newExpirationTimeSecondsFromNow == null || newExpirationTimeSecondsFromNow > 0) {
            "New expiration period MUST be null or positive."
        }
    }

    fun replaceRejectedAlgorithmPreferencesAndFeatures(addNewAlgorithms: Boolean = false) = apply {
        val features = key.primaryKey.getFeatures(referenceTime)?.features ?: 0
        val newFeatures =
            Feature.fromBitmask(features.toInt())
                // Filter out unsupported features
                .filter { policy.featurePolicy.isAcceptable(it) }
                .toSet()
                // Optionally add in new capabilities
                .plus(
                    if (addNewAlgorithms) policy.keyGenerationAlgorithmSuite.features ?: listOf()
                    else listOf())
                .toTypedArray()
                .let { Feature.toBitmask(*it) }

        // Hash Algs
        val hashAlgs = key.primaryKey.hashAlgorithmPreferences.toHashAlgorithms()
        val newHashAlgs =
            hashAlgs
                // Filter out unsupported hash algorithms
                .filter { policy.dataSignatureHashAlgorithmPolicy.isAcceptable(it) }
                // Optionally add in new hash algorithms
                .plus(
                    if (addNewAlgorithms)
                        policy.keyGenerationAlgorithmSuite.hashAlgorithms ?: listOf()
                    else listOf())
                .toSet()

        // Sym Algs
        val symAlgs = key.primaryKey.symmetricCipherPreferences.toSymmetricKeyAlgorithms()
        val newSymAlgs =
            symAlgs
                .filter {
                    policy.messageEncryptionAlgorithmPolicy.symmetricAlgorithmPolicy.isAcceptable(
                        it)
                }
                .plus(
                    if (addNewAlgorithms)
                        policy.keyGenerationAlgorithmSuite.symmetricKeyAlgorithms ?: listOf()
                    else listOf())
                .toSet()

        // Comp Algs
        val compAlgs = key.primaryKey.compressionAlgorithmPreferences.toCompressionAlgorithms()
        val newCompAlgs =
            compAlgs
                .filter { policy.compressionAlgorithmPolicy.isAcceptable(it) }
                .plus(
                    if (addNewAlgorithms)
                        policy.keyGenerationAlgorithmSuite.compressionAlgorithms ?: listOf()
                    else listOf())
                .toSet()

        // AEAD Prefs
        val aeadAlgs = key.primaryKey.aeadCipherSuitePreferences.toAEADCipherModes()
        val newAeadAlgs =
            aeadAlgs
                .filter {
                    policy.messageEncryptionAlgorithmPolicy.isAcceptable(
                        MessageEncryptionMechanism.aead(
                            it.ciphermode.algorithmId, it.aeadAlgorithm.algorithmId))
                }
                .plus(policy.keyGenerationAlgorithmSuite.aeadAlgorithms ?: listOf())
                .toSet()

        if (features != newFeatures ||
            hashAlgs != newHashAlgs ||
            symAlgs != newSymAlgs ||
            compAlgs != newCompAlgs ||
            aeadAlgs != newAeadAlgs) {
            keyEditor.addDirectKeySignature(
                SignatureParameters.Callback.modifyHashedSubpackets { sigGen ->
                    sigGen.apply {
                        setKeyFlags(key.primaryKey.keyFlags?.flags ?: 0)
                        setFeature(true, newFeatures)
                        setPreferredHashAlgorithms(
                            true, newHashAlgs.map { it.algorithmId }.toIntArray())
                        setPreferredSymmetricAlgorithms(
                            true, newSymAlgs.map { it.algorithmId }.toIntArray())
                        setPreferredCompressionAlgorithms(
                            true, newCompAlgs.map { it.algorithmId }.toIntArray())
                        setPreferredAEADCiphersuites(
                            true,
                            newAeadAlgs
                                .map {
                                    Combination(
                                        it.ciphermode.algorithmId, it.aeadAlgorithm.algorithmId)
                                }
                                .toTypedArray())
                    }
                })
        }
    }

    fun replaceWeakSubkeys(
        revokeWeakKeys: Boolean = true,
        signingKeysOnly: Boolean
    ): OpenPGPKeyUpdater = apply {
        replaceWeakSigningSubkeys(revokeWeakKeys)
        if (!signingKeysOnly) {
            replaceWeakEncryptionSubkeys(revokeWeakKeys)
        }
    }

    fun replaceWeakEncryptionSubkeys(
        revokeWeakKeys: Boolean,
        keyPairGeneratorCallback: KeyPairGeneratorCallback =
            KeyPairGeneratorCallback.encryptionKey()
    ) {
        val weakEncryptionKeys =
            key.getEncryptionKeys(referenceTime).filterNot {
                policy.publicKeyAlgorithmPolicy.isAcceptable(
                    it.algorithm, it.pgpPublicKey.bitStrength)
            }

        if (weakEncryptionKeys.isNotEmpty()) {
            keyEditor.addEncryptionSubkey(keyPairGeneratorCallback)
        }

        if (revokeWeakKeys) {
            weakEncryptionKeys
                .filterNot { it.keyIdentifier.matches(key.primaryKey.keyIdentifier) }
                .forEach { keyEditor.revokeComponentKey(it) }
        }
    }

    fun replaceWeakSigningSubkeys(
        revokeWeakKeys: Boolean,
        keyPairGenerator: PGPKeyPairGenerator = provideKeyPairGenerator(),
        keyPairGeneratorCallback: KeyPairGeneratorCallback = KeyPairGeneratorCallback.signingKey()
    ) {
        val weakSigningKeys =
            key.getSigningKeys(referenceTime).filterNot {
                policy.publicKeyAlgorithmPolicy.isAcceptable(
                    it.algorithm, it.pgpPublicKey.bitStrength)
            }

        if (weakSigningKeys.isNotEmpty()) {
            keyEditor.addSigningSubkey(keyPairGeneratorCallback)
        }

        if (revokeWeakKeys) {
            weakSigningKeys
                .filterNot { it.keyIdentifier.matches(key.primaryKey.keyIdentifier) }
                .forEach { keyEditor.revokeComponentKey(it) }
        }

        keyPairGeneratorCallback.generateFrom(keyPairGenerator)
    }

    private fun provideKeyPairGenerator(): PGPKeyPairGenerator {
        return api.implementation
            .pgpKeyPairGeneratorProvider()
            .get(key.primaryKey.getKeyVersion().numeric, referenceTime)
    }

    fun finish(): OpenPGPKey {
        return keyEditor.done()
    }

    companion object {
        const val SECOND: Long = 1000
        const val MINUTE: Long = 60 * SECOND
        const val HOUR: Long = 60 * MINUTE
        const val DAY: Long = 24 * HOUR
        const val YEAR: Long = 365 * DAY
        const val _5YEARS: Long = 5 * YEAR
    }
}
