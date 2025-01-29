// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.xdh_legacy

import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

class XDHLegacy private constructor(spec: XDHLegacySpec) : KeyType {
    override val name = "XDH"
    override val algorithm = PublicKeyAlgorithm.ECDH
    override val bitStrength = spec.bitStrength

    override fun generateKeyPair(generator: PGPKeyPairGenerator): PGPKeyPair {
        return generator.generateLegacyX25519KeyPair()
    }

    companion object {
        @JvmStatic fun fromSpec(spec: XDHLegacySpec) = XDHLegacy(spec)
    }
}
