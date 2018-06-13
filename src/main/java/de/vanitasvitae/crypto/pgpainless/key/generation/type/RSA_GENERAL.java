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
import java.security.spec.RSAKeyGenParameterSpec;

import de.vanitasvitae.crypto.pgpainless.algorithm.PublicKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.length.RsaLength;

public class RSA_GENERAL implements KeyType {

    private final RsaLength length;

    RSA_GENERAL(RsaLength length) {
        this.length = length;
    }

    public static RSA_GENERAL withLength(RsaLength length) {
        return new RSA_GENERAL(length);
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
