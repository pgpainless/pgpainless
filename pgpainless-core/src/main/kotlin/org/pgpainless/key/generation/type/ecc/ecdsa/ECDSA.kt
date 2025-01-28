// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.ecc.ecdsa

import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.ecc.EllipticCurve

class ECDSA private constructor(val curve: EllipticCurve) : KeyType {
    override val name = "ECDSA"
    override val algorithm = PublicKeyAlgorithm.ECDSA
    override val bitStrength = curve.bitStrength
    override val algorithmSpec = ECNamedCurveGenParameterSpec(curve.curveName)

    override fun generateKeyPair(generator: PGPKeyPairGenerator): PGPKeyPair {
        return ECUtil.getNamedCurveOid(curve.curveName).let { generator.generateECDSAKeyPair(it) }
    }

    companion object {
        @JvmStatic fun fromCurve(curve: EllipticCurve) = ECDSA(curve)
    }
}
