// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.eddsa_legacy

import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

class EdDSALegacy private constructor(val curve: EdDSALegacyCurve) : KeyType {
    override val name = "EdDSA"
    override val algorithm = PublicKeyAlgorithm.EDDSA_LEGACY
    override val bitStrength = curve.bitStrength

    override fun generateKeyPair(generator: PGPKeyPairGenerator): PGPKeyPair {
        return generator.generateLegacyEd25519KeyPair()
    }

    companion object {
        @JvmStatic fun fromCurve(curve: EdDSALegacyCurve) = EdDSALegacy(curve)
    }
}
