// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.xdh;

import javax.annotation.Nonnull;

public enum XDHSpec {
    _X25519("X25519", "curve25519"),
    ;

    final String name;
    final String curveName;

    XDHSpec(@Nonnull String name, @Nonnull String curveName) {
        this.name = name;
        this.curveName = curveName;
    }

    public String getName() {
        return name;
    }

    public String getCurveName() {
        return curveName;
    }
}
