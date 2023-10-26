// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.eddsa

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

class EdDSA private constructor(val curve: EdDSACurve) : KeyType {
    override val name = "EdDSA"
    override val algorithm = PublicKeyAlgorithm.EDDSA
    override val bitStrength = curve.bitStrength
    override val algorithmSpec = ECNamedCurveGenParameterSpec(curve.curveName)

    companion object {
        @JvmStatic fun fromCurve(curve: EdDSACurve) = EdDSA(curve)
    }
}
