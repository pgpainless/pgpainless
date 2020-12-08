/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.generation.type.ecdsa;


import java.security.spec.AlgorithmParameterSpec;
import javax.annotation.Nonnull;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.EllipticCurve;
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
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ECNamedCurveGenParameterSpec(curve.getName());
    }
}
