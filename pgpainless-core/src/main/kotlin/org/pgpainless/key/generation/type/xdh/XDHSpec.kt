// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.xdh

enum class XDHSpec(val algorithmName: String, val curveName: String, val bitStrength: Int) {
    _X25519("X25519", "curve25519", 256),
    ;

    fun getName() = algorithmName
}
