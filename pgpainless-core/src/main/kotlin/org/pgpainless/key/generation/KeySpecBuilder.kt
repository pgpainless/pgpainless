// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.util.*
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.*
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil

class KeySpecBuilder(
    private val type: KeyType,
    private val keyFlags: List<KeyFlag>,
) : KeySpecBuilderInterface {

    private val hashedSubpackets: SelfSignatureSubpackets = SignatureSubpackets()
    private val algorithmSuite: AlgorithmSuite =
        PGPainless.getInstance().algorithmPolicy.keyGenerationAlgorithmSuite
    private var preferredCompressionAlgorithms: Set<CompressionAlgorithm>? =
        algorithmSuite.compressionAlgorithms
    private var preferredHashAlgorithms: Set<HashAlgorithm>? = algorithmSuite.hashAlgorithms
    private var preferredSymmetricAlgorithms: Set<SymmetricKeyAlgorithm>? =
        algorithmSuite.symmetricKeyAlgorithms
    private var preferredAEADAlgorithms: Set<AEADCipherMode>? = algorithmSuite.aeadAlgorithms
    private var features: Set<Feature>? = algorithmSuite.features
    private var keyCreationDate: Date? = null

    constructor(type: KeyType, vararg keyFlags: KeyFlag) : this(type, listOf(*keyFlags))

    init {
        SignatureSubpacketsUtil.assureKeyCanCarryFlags(type, *keyFlags.toTypedArray())
    }

    override fun overridePreferredCompressionAlgorithms(
        vararg algorithms: CompressionAlgorithm
    ): KeySpecBuilder = apply {
        this.preferredCompressionAlgorithms = if (algorithms.isEmpty()) null else algorithms.toSet()
    }

    override fun overridePreferredHashAlgorithms(vararg algorithms: HashAlgorithm): KeySpecBuilder =
        apply {
            this.preferredHashAlgorithms = if (algorithms.isEmpty()) null else algorithms.toSet()
        }

    override fun overridePreferredSymmetricKeyAlgorithms(
        vararg algorithms: SymmetricKeyAlgorithm
    ): KeySpecBuilder = apply {
        require(!algorithms.contains(SymmetricKeyAlgorithm.NULL)) {
            "NULL (unencrypted) is an invalid symmetric key algorithm preference."
        }
        this.preferredSymmetricAlgorithms = if (algorithms.isEmpty()) null else algorithms.toSet()
    }

    override fun overridePreferredAEADAlgorithms(
        vararg algorithms: AEADCipherMode
    ): KeySpecBuilder = apply {
        this.preferredAEADAlgorithms = if (algorithms.isEmpty()) null else algorithms.toSet()
    }

    override fun overrideFeatures(vararg features: Feature): KeySpecBuilder = apply {
        this.features = if (features.isEmpty()) null else features.toSet()
    }

    override fun setKeyCreationDate(creationDate: Date): KeySpecBuilder = apply {
        this.keyCreationDate = creationDate
    }

    override fun build(): KeySpec {
        return hashedSubpackets
            .apply {
                setKeyFlags(keyFlags)
                preferredCompressionAlgorithms?.let { setPreferredCompressionAlgorithms(it) }
                preferredHashAlgorithms?.let { setPreferredHashAlgorithms(it) }
                preferredSymmetricAlgorithms?.let { setPreferredSymmetricKeyAlgorithms(it) }
                preferredAEADAlgorithms?.let { setPreferredAEADCiphersuites(it) }
                features?.let { setFeatures(*it.toTypedArray()) }
            }
            .let { KeySpec(type, hashedSubpackets as SignatureSubpackets, false, keyCreationDate) }
    }
}
