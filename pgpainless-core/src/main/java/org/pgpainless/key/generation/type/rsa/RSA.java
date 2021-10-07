// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.rsa;

import javax.annotation.Nonnull;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

/**
 * Key type that specifies the RSA_GENERAL algorithm.
 */
public class RSA implements KeyType {

    private final RsaLength length;

    RSA(@Nonnull RsaLength length) {
        this.length = length;
    }

    public static RSA withLength(@Nonnull RsaLength length) {
        return new RSA(length);
    }

    @Override
    public String getName() {
        return "RSA";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.RSA_GENERAL;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new RSAKeyGenParameterSpec(length.getLength(), RSAKeyGenParameterSpec.F4);
    }
}
