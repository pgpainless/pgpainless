package org.pgpainless.key.generation.type;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.curve.XDHCurve;

public class XDH implements KeyType {

    private XDHCurve curve;

    private XDH(XDHCurve curve) {
        this.curve = curve;
    }

    public static XDH fromCurve(XDHCurve curve) {
        return new XDH(curve);
    }

    @Override
    public String getName() {
        return "XDH";
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
