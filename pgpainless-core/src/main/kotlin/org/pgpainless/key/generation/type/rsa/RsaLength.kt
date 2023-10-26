// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.rsa

import org.pgpainless.key.generation.type.KeyLength

enum class RsaLength(override val length: Int) : KeyLength {
    @Deprecated("1024 bits are considered too weak for RSA nowadays.", ReplaceWith("_3072"))
    _1024(1024),
    @Deprecated("2048 bits are considered too weak for RSA nowadays.", ReplaceWith("_3072"))
    _2048(2048),
    _3072(3072),
    _4096(4096),
    _8192(8192)
}
