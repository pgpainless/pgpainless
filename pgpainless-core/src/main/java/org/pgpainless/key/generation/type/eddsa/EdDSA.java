// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.eddsa;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

/**
 * Edwards-curve Digital Signature Algorithm (EdDSA).
 */
public final class EdDSA implements KeyType {

    private final EdDSACurve curve;

    private EdDSA(EdDSACurve curve) {
        this.curve = curve;
    }

    public static EdDSA fromCurve(EdDSACurve curve) {
        return new EdDSA(curve);
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
