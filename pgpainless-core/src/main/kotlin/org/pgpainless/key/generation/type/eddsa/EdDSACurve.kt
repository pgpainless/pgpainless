// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.eddsa

enum class EdDSACurve(val curveName: String, val bitStrength: Int) {
    _Ed25519("ed25519", 256),
    ;

    fun getName() = curveName
}
