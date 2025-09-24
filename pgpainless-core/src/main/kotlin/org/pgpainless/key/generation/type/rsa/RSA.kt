// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.rsa

import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

/** Key type that specifies the RSA_GENERAL algorithm. */
class RSA private constructor(length: RsaLength) : KeyType {

    override val name = "RSA"
    override val algorithm = PublicKeyAlgorithm.RSA_GENERAL
    override val bitStrength = length.length

    override fun generateKeyPair(generator: PGPKeyPairGenerator): PGPKeyPair {
        return generator.generateRsaKeyPair(bitStrength)
    }

    companion object {
        @JvmStatic fun withLength(length: RsaLength) = RSA(length)
    }
}
