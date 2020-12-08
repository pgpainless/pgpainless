/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.generation.type.eddsa;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

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
