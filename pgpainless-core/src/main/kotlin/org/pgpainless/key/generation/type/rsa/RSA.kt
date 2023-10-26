// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.rsa

import java.security.spec.RSAKeyGenParameterSpec
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

/** Key type that specifies the RSA_GENERAL algorithm. */
class RSA private constructor(length: RsaLength) : KeyType {

    override val name = "RSA"
    override val algorithm = PublicKeyAlgorithm.RSA_GENERAL
    override val bitStrength = length.length
    override val algorithmSpec = RSAKeyGenParameterSpec(length.length, RSAKeyGenParameterSpec.F4)

    companion object {
        @JvmStatic fun withLength(length: RsaLength) = RSA(length)
    }
}
