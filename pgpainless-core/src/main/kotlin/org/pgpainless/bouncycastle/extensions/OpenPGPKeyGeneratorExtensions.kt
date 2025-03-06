// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator
import org.pgpainless.algorithm.AEADCipherMode
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm

/**
 * Apply different algorithm preferences (features, symmetric-key-, hash-, compression- and AEAD
 * algorithm preferences to the [OpenPGPKeyGenerator] for key generation. The preferences will be
 * set on preference-signatures on the generated keys.
 *
 * @param algorithms algorithm suite
 * @return this
 */
fun OpenPGPKeyGenerator.setAlgorithmSuite(algorithms: AlgorithmSuite): OpenPGPKeyGenerator {
    setDefaultFeatures(true, algorithms.features)
    setDefaultSymmetricKeyPreferences(true, algorithms.symmetricKeyAlgorithms)
    setDefaultHashAlgorithmPreferences(true, algorithms.hashAlgorithms)
    setDefaultCompressionAlgorithmPreferences(true, algorithms.compressionAlgorithms)
    setDefaultAeadAlgorithmPreferences(false, algorithms.aeadAlgorithms)
    return this
}

fun OpenPGPKeyGenerator.setDefaultFeatures(
    critical: Boolean = true,
    features: Set<Feature>
): OpenPGPKeyGenerator {
    this.setDefaultFeatures {
        val b = Feature.toBitmask(*features.toTypedArray())
        it.apply { setFeature(critical, b) }
    }
    return this
}

/**
 * Define [SymmetricKeyAlgorithms][SymmetricKeyAlgorithm] that will be applied as symmetric key
 * algorithm preferences to preference-signatures on freshly generated keys.
 *
 * @param critical whether to mark the preference subpacket as critical
 * @param symmetricKeyAlgorithms ordered set of preferred symmetric key algorithms
 * @return this
 */
fun OpenPGPKeyGenerator.setDefaultSymmetricKeyPreferences(
    critical: Boolean = true,
    symmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>?
): OpenPGPKeyGenerator = apply {
    symmetricKeyAlgorithms?.let { algorithms ->
        this.setDefaultSymmetricKeyPreferences {
            val algorithmIds = algorithms.map { a -> a.algorithmId }.toIntArray()
            it.apply { setPreferredSymmetricAlgorithms(critical, algorithmIds) }
        }
    }
}

/**
 * Define [HashAlgorithms][HashAlgorithm] that will be applied as hash algorithm preferences to
 * preference-signatures on freshly generated keys.
 *
 * @param critical whether to mark the preference subpacket as critical
 * @param hashAlgorithms ordered set of preferred hash algorithms
 * @return this
 */
fun OpenPGPKeyGenerator.setDefaultHashAlgorithmPreferences(
    critical: Boolean = true,
    hashAlgorithms: Set<HashAlgorithm>?
): OpenPGPKeyGenerator = apply {
    hashAlgorithms?.let { algorithms ->
        this.setDefaultHashAlgorithmPreferences {
            val algorithmIds = algorithms.map { a -> a.algorithmId }.toIntArray()
            it.apply { setPreferredHashAlgorithms(critical, algorithmIds) }
        }
    }
}

/**
 * Define [CompressionAlgorithms][CompressionAlgorithm] that will be applied as compression
 * algorithm preferences to preference-signatures on freshly generated keys.
 *
 * @param critical whether to mark the preference subpacket as critical
 * @param compressionAlgorithms ordered set of preferred compression algorithms
 * @return this
 */
fun OpenPGPKeyGenerator.setDefaultCompressionAlgorithmPreferences(
    critical: Boolean = true,
    compressionAlgorithms: Set<CompressionAlgorithm>?
): OpenPGPKeyGenerator = apply {
    compressionAlgorithms?.let { algorithms ->
        this.setDefaultCompressionAlgorithmPreferences {
            val algorithmIds = algorithms.map { a -> a.algorithmId }.toIntArray()
            it.apply { setPreferredCompressionAlgorithms(critical, algorithmIds) }
        }
    }
}

/**
 * Define [AEADCipherModes][AEADCipherMode] that will be applied as AEAD algorithm preferences to
 * preference signatures on freshly generated keys.
 *
 * @param critical whether to mark the preferences subpacket as critical
 * @param aeadAlgorithms ordered set of AEAD preferences
 * @return this
 */
fun OpenPGPKeyGenerator.setDefaultAeadAlgorithmPreferences(
    critical: Boolean = false,
    aeadAlgorithms: Set<AEADCipherMode>?
): OpenPGPKeyGenerator = apply {
    aeadAlgorithms?.let { algorithms ->
        this.setDefaultAeadAlgorithmPreferences {
            val builder = PreferredAEADCiphersuites.builder(critical)
            for (ciphermode: AEADCipherMode in algorithms) {
                builder.addCombination(
                    ciphermode.ciphermode.algorithmId, ciphermode.aeadAlgorithm.algorithmId)
            }
            it.apply { setPreferredAEADCiphersuites(builder) }
        }
    }
}
