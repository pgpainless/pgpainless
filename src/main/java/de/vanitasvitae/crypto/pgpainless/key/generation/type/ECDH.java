package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import java.security.spec.AlgorithmParameterSpec;

import de.vanitasvitae.crypto.pgpainless.algorithm.PublicKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.curve.EllipticCurve;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

public class ECDH implements KeyType {

    private final EllipticCurve curve;

    ECDH(EllipticCurve curve) {
        this.curve = curve;
    }

    public static ECDH fromCurve(EllipticCurve curve) {
        return new ECDH(curve);
    }

    @Override
    public String getName() {
        return "ECDH";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ECDH;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ECNamedCurveGenParameterSpec(curve.getName());
    }
}
