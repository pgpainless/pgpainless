// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.xdh;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

public final class XDH implements KeyType {

    private final XDHSpec spec;

    private XDH(XDHSpec spec) {
        this.spec = spec;
    }

    public static XDH fromSpec(XDHSpec spec) {
        return new XDH(spec);
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
        return new ECNamedCurveGenParameterSpec(spec.getName());
    }

}
