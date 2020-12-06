package org.pgpainless.key.generation.type.curve;

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
