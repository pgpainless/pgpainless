// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.elgamal

import org.bouncycastle.jce.spec.ElGamalParameterSpec
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

/**
 * ElGamal encryption only key type.
 *
 * @deprecated the use of ElGamal is not recommended anymore.
 */
@Deprecated("The use of ElGamal is not recommended anymore.")
class ElGamal private constructor(length: ElGamalLength) : KeyType {

    override val name = "ElGamal"
    override val algorithm = PublicKeyAlgorithm.ELGAMAL_ENCRYPT
    override val bitStrength = length.length
    override val algorithmSpec = ElGamalParameterSpec(length.p, length.g)

    companion object {
        @JvmStatic
        fun withLength(length: ElGamalLength) = ElGamal(length)
    }
}