// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.xdh

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

class XDH private constructor(spec: XDHSpec): KeyType {
    override val name = "XDH"
    override val algorithm = PublicKeyAlgorithm.ECDH
    override val bitStrength = spec.bitStrength
    override val algorithmSpec = ECNamedCurveGenParameterSpec(spec.algorithmName)

    companion object {
        @JvmStatic
        fun fromSpec(spec: XDHSpec) = XDH(spec)
    }
}