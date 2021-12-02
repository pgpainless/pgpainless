// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.elgamal;

import java.security.spec.AlgorithmParameterSpec;
import javax.annotation.Nonnull;

import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

/**
 * ElGamal encryption only key type.
 */
public final class ElGamal implements KeyType {

    private final ElGamalLength length;

    private ElGamal(@Nonnull ElGamalLength length) {
        this.length = length;
    }

    public static ElGamal withLength(ElGamalLength length) {
        return new ElGamal(length);
    }

    @Override
    public String getName() {
        return "ElGamal";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ELGAMAL_ENCRYPT;
    }

    @Override
    public int getBitStrength() {
        return length.getLength();
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ElGamalParameterSpec(length.getP(), length.getG());
    }

}
