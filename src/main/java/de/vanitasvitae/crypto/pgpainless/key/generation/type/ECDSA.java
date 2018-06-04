package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import de.vanitasvitae.crypto.pgpainless.algorithm.PublicKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.curve.EllipticCurve;

public class ECDSA extends ECDH {

    ECDSA(EllipticCurve curve) {
        super(curve);
    }

    public static ECDSA fromCurve(EllipticCurve curve) {
        return new ECDSA(curve);
    }

    @Override
    public String getName() {
        return "ECDSA";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ECDSA;
    }
}
