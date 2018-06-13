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
