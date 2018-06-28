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

import org.bouncycastle.bcpg.HashAlgorithmTags;

public enum HashAlgorithm {

    MD5(        HashAlgorithmTags.MD5),
    SHA1(       HashAlgorithmTags.SHA1),
    RIPEMD160(  HashAlgorithmTags.RIPEMD160),
    DOUBLE_SHA( HashAlgorithmTags.DOUBLE_SHA),
    MD2(        HashAlgorithmTags.MD2),
    TIGER_192(  HashAlgorithmTags.TIGER_192),
    HAVAL_5_160(HashAlgorithmTags.HAVAL_5_160),
    SHA256(     HashAlgorithmTags.SHA256),
    SHA384(     HashAlgorithmTags.SHA384),
    SHA512(     HashAlgorithmTags.SHA512),
    SHA224(     HashAlgorithmTags.SHA224),
    ;
    //                                                         Coincidence? I don't this so...
    private static final Map<Integer, HashAlgorithm> MAP = new HashMap<>();

    static {
        for (HashAlgorithm h : HashAlgorithm.values()) {
            MAP.put(h.algorithmId, h);
        }
    }

    public static HashAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    HashAlgorithm(int id) {
        this.algorithmId = id;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }
}
