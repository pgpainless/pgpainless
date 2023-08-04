// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

class AlgorithmSuite(
        symmetricKeyAlgorithms: List<SymmetricKeyAlgorithm>,
        hashAlgorithms: List<HashAlgorithm>,
        compressionAlgorithms: List<CompressionAlgorithm>) {

    val symmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm> = symmetricKeyAlgorithms.toSet()
    val hashAlgorithms: Set<HashAlgorithm> = hashAlgorithms.toSet()
    val compressionAlgorithms: Set<CompressionAlgorithm> = compressionAlgorithms.toSet()

    companion object {

        @JvmStatic
        val defaultSymmetricKeyAlgorithms = listOf(
                SymmetricKeyAlgorithm.AES_256,
                SymmetricKeyAlgorithm.AES_192,
                SymmetricKeyAlgorithm.AES_128)

        @JvmStatic
        val defaultHashAlgorithms = listOf(
                HashAlgorithm.SHA512,
                HashAlgorithm.SHA384,
                HashAlgorithm.SHA256,
                HashAlgorithm.SHA224)

        @JvmStatic
        val defaultCompressionAlgorithms = listOf(
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.BZIP2,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.UNCOMPRESSED)

        @JvmStatic
        val defaultAlgorithmSuite = AlgorithmSuite(
                defaultSymmetricKeyAlgorithms,
                defaultHashAlgorithms,
                 defaultCompressionAlgorithms)
    }

}