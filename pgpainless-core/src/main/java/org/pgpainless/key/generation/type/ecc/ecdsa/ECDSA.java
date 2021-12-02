// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.ecc.ecdsa;


import java.security.spec.AlgorithmParameterSpec;
import javax.annotation.Nonnull;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.KeyType;

public final class ECDSA implements KeyType {

    private final EllipticCurve curve;

    private ECDSA(@Nonnull EllipticCurve curve) {
        this.curve = curve;
    }

    public static ECDSA fromCurve(@Nonnull EllipticCurve curve) {
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

    @Override
    public int getBitStrength() {
        return curve.getBitStrength();
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ECNamedCurveGenParameterSpec(curve.getName());
    }

}
