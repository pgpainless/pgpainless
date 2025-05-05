// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.util.*
import org.pgpainless.algorithm.AEADCipherMode
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

data class KeySpec(
    val keyType: KeyType,
    val keyFlags: List<KeyFlag>,
    val preferredCompressionAlgorithmsOverride: Set<CompressionAlgorithm>?,
    val preferredHashAlgorithmsOverride: Set<HashAlgorithm>?,
    val preferredSymmetricAlgorithmsOverride: Set<SymmetricKeyAlgorithm>?,
    val preferredAEADAlgorithmsOverride: Set<AEADCipherMode>?,
    val featuresOverride: Set<Feature>?,
    val keyCreationDate: Date?
) {

    companion object {
        @JvmStatic
        fun getBuilder(type: KeyType, vararg flags: KeyFlag) = KeySpecBuilder(type, *flags)
    }
}
