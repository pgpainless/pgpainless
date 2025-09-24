// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.util.*
import org.pgpainless.algorithm.*
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil

class KeySpecBuilder(
    private val type: KeyType,
    private val keyFlags: List<KeyFlag>,
) : KeySpecBuilderInterface {

    private var preferredCompressionAlgorithms: Set<CompressionAlgorithm>? = null
    private var preferredHashAlgorithms: Set<HashAlgorithm>? = null
    private var preferredSymmetricAlgorithms: Set<SymmetricKeyAlgorithm>? = null
    private var preferredAEADAlgorithms: Set<AEADCipherMode>? = null
    private var features: Set<Feature>? = null
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
        return KeySpec(
            type,
            keyFlags,
            preferredCompressionAlgorithms,
            preferredHashAlgorithms,
            preferredSymmetricAlgorithms,
            preferredAEADAlgorithms,
            features,
            keyCreationDate)
    }
}
