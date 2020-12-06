package org.pgpainless.key.generation.type;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.curve.EdDSACurve;

public class EDDSA implements KeyType {

    private final EdDSACurve curve;

    private EDDSA(EdDSACurve curve) {
        this.curve = curve;
    }

    public static EDDSA fromCurve(EdDSACurve curve) {
        return new EDDSA(curve);
    }

    @Override
    public String getName() {
        return "EdDSA";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.EDDSA;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ECNamedCurveGenParameterSpec(curve.getName());
    }
}
