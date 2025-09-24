// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

class AlgorithmSuite
private constructor(
    val symmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>?,
    val hashAlgorithms: Set<HashAlgorithm>?,
    val compressionAlgorithms: Set<CompressionAlgorithm>?,
    val aeadAlgorithms: Set<AEADCipherMode>?,
    val features: Set<Feature>?
) {

    constructor(
        symmetricKeyAlgorithms: List<SymmetricKeyAlgorithm>?,
        hashAlgorithms: List<HashAlgorithm>?,
        compressionAlgorithms: List<CompressionAlgorithm>?,
        aeadAlgorithms: List<AEADCipherMode>?,
        features: List<Feature>?
    ) : this(
        symmetricKeyAlgorithms?.toSet(),
        hashAlgorithms?.toSet(),
        compressionAlgorithms?.toSet(),
        aeadAlgorithms?.toSet(),
        features?.toSet())

    fun modify(): Builder = Builder(this)

    class Builder(suite: AlgorithmSuite? = null) {
        private var symmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>? =
            suite?.symmetricKeyAlgorithms
        private var hashAlgorithms: Set<HashAlgorithm>? = suite?.hashAlgorithms
        private var compressionAlgorithms: Set<CompressionAlgorithm>? = suite?.compressionAlgorithms
        private var aeadAlgorithms: Set<AEADCipherMode>? = suite?.aeadAlgorithms
        private var features: Set<Feature>? = suite?.features

        fun overrideSymmetricKeyAlgorithms(
            vararg symmetricKeyAlgorithms: SymmetricKeyAlgorithm
        ): Builder = overrideSymmetricKeyAlgorithms(symmetricKeyAlgorithms.toSet())

        fun overrideSymmetricKeyAlgorithms(
            symmetricKeyAlgorithms: Collection<SymmetricKeyAlgorithm>?
        ): Builder = apply { this.symmetricKeyAlgorithms = symmetricKeyAlgorithms?.toSet() }

        fun overrideHashAlgorithms(vararg hashAlgorithms: HashAlgorithm): Builder =
            overrideHashAlgorithms(hashAlgorithms.toSet())

        fun overrideHashAlgorithms(hashAlgorithms: Collection<HashAlgorithm>?): Builder = apply {
            this.hashAlgorithms = hashAlgorithms?.toSet()
        }

        fun overrideCompressionAlgorithms(
            vararg compressionAlgorithms: CompressionAlgorithm
        ): Builder = overrideCompressionAlgorithms(compressionAlgorithms.toSet())

        fun overrideCompressionAlgorithms(
            compressionAlgorithms: Collection<CompressionAlgorithm>?
        ): Builder = apply { this.compressionAlgorithms = compressionAlgorithms?.toSet() }

        fun overrideAeadAlgorithms(vararg aeadAlgorithms: AEADCipherMode): Builder =
            overrideAeadAlgorithms(aeadAlgorithms.toSet())

        fun overrideAeadAlgorithms(aeadAlgorithms: Collection<AEADCipherMode>?): Builder = apply {
            this.aeadAlgorithms = aeadAlgorithms?.toSet()
        }

        fun overrideFeatures(vararg features: Feature): Builder = overrideFeatures(features.toSet())

        fun overrideFeatures(features: Collection<Feature>?): Builder = apply {
            this.features = features?.toSet()
        }

        fun build(): AlgorithmSuite {
            return AlgorithmSuite(
                symmetricKeyAlgorithms,
                hashAlgorithms,
                compressionAlgorithms,
                aeadAlgorithms,
                features)
        }
    }

    companion object {

        @JvmStatic
        fun emptyBuilder(): Builder {
            return Builder()
        }

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
