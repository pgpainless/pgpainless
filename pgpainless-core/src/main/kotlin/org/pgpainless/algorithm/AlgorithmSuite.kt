// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction

class AlgorithmSuite(
    symmetricKeyAlgorithms: List<SymmetricKeyAlgorithm>?,
    hashAlgorithms: List<HashAlgorithm>?,
    compressionAlgorithms: List<CompressionAlgorithm>?,
    aeadAlgorithms: List<AEADCipherMode>?,
    features: List<Feature>
) {

    val symmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>? = symmetricKeyAlgorithms?.toSet()
    val hashAlgorithms: Set<HashAlgorithm>? = hashAlgorithms?.toSet()
    val compressionAlgorithms: Set<CompressionAlgorithm>? = compressionAlgorithms?.toSet()
    val aeadAlgorithms: Set<AEADCipherMode>? = aeadAlgorithms?.toSet()
    val features: FeatureSet = FeatureSet(features.toSet())

    class FeatureSet(val features: Set<Feature>) {
        fun toSignatureSubpacketsFunction(critical: Boolean = true): SignatureSubpacketsFunction {
            return SignatureSubpacketsFunction {
                val b = Feature.toBitmask(*features.toTypedArray())
                it.apply { setFeature(critical, b) }
            }
        }
    }

    companion object {

        @JvmStatic
        val defaultSymmetricKeyAlgorithms =
            listOf(
                SymmetricKeyAlgorithm.AES_256,
                SymmetricKeyAlgorithm.AES_192,
                SymmetricKeyAlgorithm.AES_128)

        @JvmStatic
        val defaultHashAlgorithms =
            listOf(
                HashAlgorithm.SHA512,
                HashAlgorithm.SHA384,
                HashAlgorithm.SHA256,
                HashAlgorithm.SHA224)

        @JvmStatic
        val defaultCompressionAlgorithms =
            listOf(
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.BZIP2,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.UNCOMPRESSED)

        @JvmStatic
        val defaultAEADAlgorithmSuites =
            listOf(
                AEADCipherMode(AEADAlgorithm.EAX, SymmetricKeyAlgorithm.AES_256),
                AEADCipherMode(AEADAlgorithm.OCB, SymmetricKeyAlgorithm.AES_256),
                AEADCipherMode(AEADAlgorithm.GCM, SymmetricKeyAlgorithm.AES_256),
                AEADCipherMode(AEADAlgorithm.EAX, SymmetricKeyAlgorithm.AES_192),
                AEADCipherMode(AEADAlgorithm.EAX, SymmetricKeyAlgorithm.AES_192))

        @JvmStatic
        val defaultFeatures =
            listOf(Feature.MODIFICATION_DETECTION, Feature.MODIFICATION_DETECTION_2)

        @JvmStatic
        val defaultAlgorithmSuite =
            AlgorithmSuite(
                defaultSymmetricKeyAlgorithms,
                defaultHashAlgorithms,
                defaultCompressionAlgorithms,
                defaultAEADAlgorithmSuites,
                defaultFeatures)
    }
}
