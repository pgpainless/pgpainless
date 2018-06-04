package de.vanitasvitae.crypto.pgpainless.key.generation.type.curve;

public enum EllipticCurve {
    _P256("P-256"),
    ;

    private final String name;

    EllipticCurve(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
