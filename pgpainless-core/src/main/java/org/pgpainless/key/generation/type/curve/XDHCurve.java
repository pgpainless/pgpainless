package org.pgpainless.key.generation.type.curve;

import javax.annotation.Nonnull;

public enum XDHCurve {
    _X25519("X25519"),
    ;

    final String name;

    XDHCurve(@Nonnull String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
