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
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-koch-eddsa-for-openpgp/">EdDSA for OpenPGP</a>
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
    public int getBitStrength() {
        return curve.getBitStrength();
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ECNamedCurveGenParameterSpec(curve.getName());
    }

}
