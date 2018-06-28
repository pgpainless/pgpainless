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
package org.pgpainless.pgpainless.algorithm;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

public enum SymmetricKeyAlgorithm {

    NULL(           SymmetricKeyAlgorithmTags.NULL),
    IDEA(           SymmetricKeyAlgorithmTags.IDEA),
    TRIPLE_DES(     SymmetricKeyAlgorithmTags.TRIPLE_DES),
    CAST5(          SymmetricKeyAlgorithmTags.CAST5),
    BLOWFISH(       SymmetricKeyAlgorithmTags.BLOWFISH),
    SAFER(          SymmetricKeyAlgorithmTags.SAFER),
    DES(            SymmetricKeyAlgorithmTags.DES),
    AES_128(        SymmetricKeyAlgorithmTags.AES_128),
    AES_192(        SymmetricKeyAlgorithmTags.AES_192),
    AES_256(        SymmetricKeyAlgorithmTags.AES_256),
    TWOFISH(        SymmetricKeyAlgorithmTags.TWOFISH),
    CAMELLIA_128(   SymmetricKeyAlgorithmTags.CAMELLIA_128),
    CAMELLIA_192(   SymmetricKeyAlgorithmTags.CAMELLIA_192),
    CAMELLIA_256(   SymmetricKeyAlgorithmTags.CAMELLIA_256),
    ;

    private static final Map<Integer, SymmetricKeyAlgorithm> MAP = new HashMap<>();

    static {
        for (SymmetricKeyAlgorithm s : SymmetricKeyAlgorithm.values()) {
            MAP.put(s.algorithmId, s);
        }
    }

    public static SymmetricKeyAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    SymmetricKeyAlgorithm(int algorithmId) {
        this.algorithmId = algorithmId;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }
}
