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

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * Enumeration of possible symmetric encryption algorithms.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-9.2">RFC4880: Symmetric-Key Algorithms</a>
 */
public enum SymmetricKeyAlgorithm {

    /**
     * Plaintext or unencrypted data.
     */
    NULL            (SymmetricKeyAlgorithmTags.NULL),

    /**
     * IDEA is deprecated.
     * @deprecated use a different algorithm.
     */
    @Deprecated
    IDEA            (SymmetricKeyAlgorithmTags.IDEA),

    /**
     * TripleDES (DES-EDE - 168 bit key derived from 192).
     */
    TRIPLE_DES      (SymmetricKeyAlgorithmTags.TRIPLE_DES),

    /**
     * CAST5 (128 bit key, as per RFC2144).
     */
    CAST5           (SymmetricKeyAlgorithmTags.CAST5),

    /**
     * Blowfish (128 bit key, 16 rounds).
     */
    BLOWFISH        (SymmetricKeyAlgorithmTags.BLOWFISH),

    /**
     * Reserved in RFC4880.
     * SAFER-SK128 (13 rounds)
     */
    SAFER           (SymmetricKeyAlgorithmTags.SAFER),

    /**
     * Reserved in RFC4880.
     * Reserved for DES/SK
     */
    DES             (SymmetricKeyAlgorithmTags.DES),

    /**
     * AES with 128-bit key.
     */
    AES_128         (SymmetricKeyAlgorithmTags.AES_128),

    /**
     * AES with 192-bit key.
     */
    AES_192         (SymmetricKeyAlgorithmTags.AES_192),

    /**
     * AES with 256-bit key.
     */
    AES_256         (SymmetricKeyAlgorithmTags.AES_256),

    /**
     * Twofish with 256-bit key.
     */
    TWOFISH         (SymmetricKeyAlgorithmTags.TWOFISH),

    /**
     * Reserved for Camellia with 128-bit key.
     */
    CAMELLIA_128    (SymmetricKeyAlgorithmTags.CAMELLIA_128),

    /**
     * Reserved for Camellia with 192-bit key.
     */
    CAMELLIA_192    (SymmetricKeyAlgorithmTags.CAMELLIA_192),

    /**
     * Reserved for Camellia with 256-bit key.
     */
    CAMELLIA_256    (SymmetricKeyAlgorithmTags.CAMELLIA_256),
    ;

    private static final Map<Integer, SymmetricKeyAlgorithm> MAP = new ConcurrentHashMap<>();

    static {
        for (SymmetricKeyAlgorithm s : SymmetricKeyAlgorithm.values()) {
            MAP.put(s.algorithmId, s);
        }
    }

    /**
     * Return the {@link SymmetricKeyAlgorithm} enum that corresponds to the provided numeric id.
     * If an invalid id is provided, null is returned.
     *
     * @param id numeric algorithm id
     * @return symmetric key algorithm enum
     */
    public static SymmetricKeyAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    SymmetricKeyAlgorithm(int algorithmId) {
        this.algorithmId = algorithmId;
    }

    /**
     * Return the numeric algorithm id of the enum.
     *
     * @return numeric id
     */
    public int getAlgorithmId() {
        return algorithmId;
    }
}
