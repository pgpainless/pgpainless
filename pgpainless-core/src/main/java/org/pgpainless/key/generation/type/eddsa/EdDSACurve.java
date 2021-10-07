// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.eddsa;

import javax.annotation.Nonnull;

public enum EdDSACurve {
    _Ed25519("ed25519"),
    ;

    final String name;

    EdDSACurve(@Nonnull String curveName) {
        this.name = curveName;
    }

    public String getName() {
        return name;
    }
}
