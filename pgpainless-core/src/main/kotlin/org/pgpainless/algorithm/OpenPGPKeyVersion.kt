// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class OpenPGPKeyVersion(val numeric: Int) {
    @Deprecated("V3 keys are deprecated.") v3(3),
    v4(4),
    librePgp(5),
    v6(6),
    ;

    companion object {
        @JvmStatic
        fun from(numeric: Int): OpenPGPKeyVersion {
            return values().find { numeric == it.numeric }
                ?: throw IllegalArgumentException("Unknown key version $numeric")
        }
    }
}
