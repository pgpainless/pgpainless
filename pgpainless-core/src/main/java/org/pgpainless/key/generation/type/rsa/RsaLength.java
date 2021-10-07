// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.rsa;

import org.pgpainless.key.generation.type.KeyLength;

public enum RsaLength implements KeyLength {
    @Deprecated
    _1024(1024),
    @Deprecated
    _2048(2048),
    _3072(3072),
    _4096(4096),
    _8192(8192),
    ;

    private final int length;

    RsaLength(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }
}
