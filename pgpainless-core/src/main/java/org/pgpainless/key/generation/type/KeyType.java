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
package org.pgpainless.key.generation.type;

import java.security.spec.AlgorithmParameterSpec;

import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.ecc.ecdh.ECDH;
import org.pgpainless.key.generation.type.ecc.ecdsa.ECDSA;
import org.pgpainless.key.generation.type.eddsa.EdDSA;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.rsa.RSA;

public interface KeyType {

    /**
     * Return the encryption algorithm name.
     *
     * @return algorithm name.
     */
    String getName();

    /**
     * Return the public key algorithm.
     *
     * @return public key algorithm
     */
    PublicKeyAlgorithm getAlgorithm();

    /**
     * Return an implementation of {@link AlgorithmParameterSpec} that can be used to generate the key.
     *
     * @return algorithm parameter spec
     */
    AlgorithmParameterSpec getAlgorithmSpec();

    /**
     * Return true if the key that is generated from this type is able to carry the CERTIFY_OTHERS key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#CERTIFY_OTHER}.
     *
     * @return true if the key is able to certify others
     */
    boolean canCertify();

    static KeyType RSA(RsaLength length) {
        return RSA.withLength(length);
    }

    static KeyType ECDH(EllipticCurve curve) {
        return ECDH.fromCurve(curve);
    }

    static KeyType ECDSA(EllipticCurve curve) {
        return ECDSA.fromCurve(curve);
    }

    static KeyType EDDSA(EdDSACurve curve) {
        return EdDSA.fromCurve(curve);
    }
}
