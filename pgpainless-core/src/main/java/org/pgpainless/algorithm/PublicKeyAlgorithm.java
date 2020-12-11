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
package org.pgpainless.algorithm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

public enum PublicKeyAlgorithm {

    /**
     * RSA capable of encryption and signatures.
     */
    RSA_GENERAL     (PublicKeyAlgorithmTags.RSA_GENERAL),

    /**
     * RSA with usage encryption.
     *
     * @deprecated see https://tools.ietf.org/html/rfc4880#section-13.5
     */
    RSA_ENCRYPT     (PublicKeyAlgorithmTags.RSA_ENCRYPT),

    /**
     * RSA with usage of creating signatures.
     *
     * @deprecated see https://tools.ietf.org/html/rfc4880#section-13.5
     */
    RSA_SIGN        (PublicKeyAlgorithmTags.RSA_SIGN),

    /**
     * ElGamal with usage encryption.
     */
    ELGAMAL_ENCRYPT (PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT),

    /**
     * Digital Signature Algorithm.
     */
    DSA             (PublicKeyAlgorithmTags.DSA),

    /**
     * EC is deprecated.
     * @deprecated use {@link #ECDH} instead.
     */
    EC              (PublicKeyAlgorithmTags.EC),

    /**
     * Elliptic Curve Diffie-Hellman.
     */
    ECDH            (PublicKeyAlgorithmTags.ECDH),

    /**
     * Elliptic Curve Digital Signature Algorithm.
     */
    ECDSA           (PublicKeyAlgorithmTags.ECDSA),

    /**
     * ElGamal General.
     *
     * @deprecated see https://tools.ietf.org/html/rfc4880#section-13.8
     */
    @Deprecated
    ELGAMAL_GENERAL (PublicKeyAlgorithmTags.ELGAMAL_GENERAL),

    /**
     * Diffie-Hellman key exchange algorithm.
     */
    DIFFIE_HELLMAN  (PublicKeyAlgorithmTags.DIFFIE_HELLMAN),

    /**
     * Digital Signature Algorithm based on twisted Edwards Curves.
     */
    EDDSA           (PublicKeyAlgorithmTags.EDDSA),
    ;

    private static final Map<Integer, PublicKeyAlgorithm> MAP = new ConcurrentHashMap<>();

    static {
        for (PublicKeyAlgorithm p : PublicKeyAlgorithm.values()) {
            MAP.put(p.algorithmId, p);
        }
    }

    public static PublicKeyAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    PublicKeyAlgorithm(int algorithmId) {
        this.algorithmId = algorithmId;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }
}
