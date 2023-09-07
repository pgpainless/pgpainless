// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.ecc.ecdh

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.ecc.EllipticCurve

class ECDH private constructor(val curve: EllipticCurve) : KeyType {
    override val name = "ECDH"
    override val algorithm = PublicKeyAlgorithm.ECDH
    override val bitStrength = curve.bitStrength
    override val algorithmSpec = ECNamedCurveGenParameterSpec(curve.curveName)

    companion object {
        @JvmStatic
        fun fromCurve(curve: EllipticCurve) = ECDH(curve)
    }
}