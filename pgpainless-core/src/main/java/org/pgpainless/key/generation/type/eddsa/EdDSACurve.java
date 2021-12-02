// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.eddsa;

import javax.annotation.Nonnull;

public enum EdDSACurve {
    _Ed25519("ed25519", 256),
    ;

    final String name;
    final int bitStrength;

    EdDSACurve(@Nonnull String curveName, int bitStrength) {
        this.name = curveName;
        this.bitStrength = bitStrength;
    }

    public String getName() {
        return name;
    }

    public int getBitStrength() {
        return bitStrength;
    }
}
