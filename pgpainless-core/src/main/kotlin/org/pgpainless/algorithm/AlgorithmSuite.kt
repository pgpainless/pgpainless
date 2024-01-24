// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

class AlgorithmSuite(
    symmetricKeyAlgorithms: List<SymmetricKeyAlgorithm>,
    hashAlgorithms: List<HashAlgorithm>,
    compressionAlgorithms: List<CompressionAlgorithm>,
    features: List<Feature>
) {

    val symmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm> = symmetricKeyAlgorithms.toSet()
    val hashAlgorithms: Set<HashAlgorithm> = hashAlgorithms.toSet()
    val compressionAlgorithms: Set<CompressionAlgorithm> = compressionAlgorithms.toSet()
    val features: Set<Feature> = features.toSet()

    companion object {

        @JvmStatic
        val v4SymmetricKeyAlgorithms =
            listOf(
                SymmetricKeyAlgorithm.AES_256,
                SymmetricKeyAlgorithm.AES_192,
                SymmetricKeyAlgorithm.AES_128)

        @JvmStatic val defaultSymmetricKeyAlgorithms = v4SymmetricKeyAlgorithms

        @JvmStatic
        val v4HashAlgorithms =
            listOf(
                HashAlgorithm.SHA512,
                HashAlgorithm.SHA384,
                HashAlgorithm.SHA256,
                HashAlgorithm.SHA224)

        @JvmStatic
        val v6HashAlgorithms =
            listOf(
                HashAlgorithm.SHA3_512,
                HashAlgorithm.SHA3_256,
                HashAlgorithm.SHA512,
                HashAlgorithm.SHA384,
                HashAlgorithm.SHA256)

        @JvmStatic val defaultHashAlgorithms = v4HashAlgorithms

        @JvmStatic
        val v4CompressionAlgorithms =
            listOf(
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.BZIP2,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.UNCOMPRESSED)

        @JvmStatic
        val v6CompressionAlgorithms =
            listOf(
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.BZIP2,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.UNCOMPRESSED)

        @JvmStatic val defaultCompressionAlgorithms = v4CompressionAlgorithms

        @JvmStatic val v4Features = listOf(Feature.MODIFICATION_DETECTION)

        @JvmStatic
        val v6Features = listOf(Feature.MODIFICATION_DETECTION, Feature.MODIFICATION_DETECTION_2)

        @JvmStatic val defaultFeatures = v4Features

        @JvmStatic
        val v4AlgorithmSuite =
            AlgorithmSuite(
                v4SymmetricKeyAlgorithms, v4HashAlgorithms, v4CompressionAlgorithms, v4Features)

        @JvmStatic
        val v6AlgorithmSuite =
            AlgorithmSuite(
                v4SymmetricKeyAlgorithms, v6HashAlgorithms, v6CompressionAlgorithms, v6Features)

        @JvmStatic val defaultAlgorithmSuite = v4AlgorithmSuite
    }
}
