// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.helpers

import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction
import org.pgpainless.algorithm.AEADCipherMode
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm

class SignatureSubpacketsFunctionHelper {

    companion object {

        @JvmStatic
        fun applySymmetricAlgorithmPreferences(
            critical: Boolean = true,
            symmetricAlgorithms: Set<SymmetricKeyAlgorithm>?
        ): SignatureSubpacketsFunction {
            return symmetricAlgorithms?.let { algorithms ->
                val algorithmIds = algorithms.map { it.algorithmId }.toIntArray()
                SignatureSubpacketsFunction {
                    it.apply { setPreferredSymmetricAlgorithms(critical, algorithmIds) }
                }
            }
                ?: SignatureSubpacketsFunction { it }
        }

        @JvmStatic
        fun applyHashAlgorithmPreferences(
            critical: Boolean = true,
            hashAlgorithms: Set<HashAlgorithm>?
        ): SignatureSubpacketsFunction {
            return hashAlgorithms?.let { algorithms ->
                val algorithmIds = algorithms.map { it.algorithmId }.toIntArray()
                SignatureSubpacketsFunction {
                    it.apply { setPreferredHashAlgorithms(critical, algorithmIds) }
                }
            }
                ?: SignatureSubpacketsFunction { it }
        }

        @JvmStatic
        fun applyCompressionAlgorithmPreferences(
            critical: Boolean = true,
            compressionAlgorithms: Set<CompressionAlgorithm>?
        ): SignatureSubpacketsFunction {
            return compressionAlgorithms?.let { algorithms ->
                val algorithmIds = algorithms.map { it.algorithmId }.toIntArray()
                SignatureSubpacketsFunction {
                    it.apply { setPreferredCompressionAlgorithms(critical, algorithmIds) }
                }
            }
                ?: SignatureSubpacketsFunction { it }
        }

        @JvmStatic
        fun applyAEADAlgorithmSuites(
            critical: Boolean = true,
            aeadAlgorithms: Set<AEADCipherMode>?
        ): SignatureSubpacketsFunction {
            return aeadAlgorithms?.let { algorithms ->
                SignatureSubpacketsFunction {
                    val builder = PreferredAEADCiphersuites.builder(critical)
                    for (ciphermode: AEADCipherMode in algorithms) {
                        builder.addCombination(
                            ciphermode.ciphermode.algorithmId, ciphermode.aeadAlgorithm.algorithmId)
                    }
                    it.apply { setPreferredAEADCiphersuites(builder) }
                }
            }
                ?: SignatureSubpacketsFunction { it }
        }

        @JvmStatic
        fun applyFeatures(
            critical: Boolean = true,
            features: Set<Feature>
        ): SignatureSubpacketsFunction {
            return SignatureSubpacketsFunction {
                val b = Feature.toBitmask(*features.toTypedArray())
                it.apply { setFeature(critical, b) }
            }
        }
    }
}
