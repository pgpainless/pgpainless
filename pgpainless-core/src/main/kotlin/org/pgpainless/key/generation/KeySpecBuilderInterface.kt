// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.util.*
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm

interface KeySpecBuilderInterface {

    fun overridePreferredCompressionAlgorithms(
        vararg algorithms: CompressionAlgorithm
    ): KeySpecBuilder

    fun overridePreferredHashAlgorithms(vararg algorithms: HashAlgorithm): KeySpecBuilder

    fun overridePreferredSymmetricKeyAlgorithms(
        vararg algorithms: SymmetricKeyAlgorithm
    ): KeySpecBuilder

    fun setKeyCreationDate(creationDate: Date): KeySpecBuilder

    fun build(): KeySpec
}
