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
package org.pgpainless.key.generation.type.elgamal;

import java.security.spec.AlgorithmParameterSpec;
import javax.annotation.Nonnull;

import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

public final class ElGamal_ENCRYPT implements KeyType {

    private final ElGamalLength length;

    private ElGamal_ENCRYPT(@Nonnull ElGamalLength length) {
        this.length = length;
    }

    public static ElGamal_ENCRYPT withLength(ElGamalLength length) {
        return new ElGamal_ENCRYPT(length);
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
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ElGamalParameterSpec(length.getP(), length.getG());
    }

    @Override
    public boolean canCertify() {
        return false;
    }
}
