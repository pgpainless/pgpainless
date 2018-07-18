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

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

public enum CompressionAlgorithm {

    UNCOMPRESSED   (CompressionAlgorithmTags.UNCOMPRESSED),
    ZIP            (CompressionAlgorithmTags.ZIP),
    ZLIB           (CompressionAlgorithmTags.ZLIB),
    BZIP2          (CompressionAlgorithmTags.BZIP2),
    ;

    private static final Map<Integer, CompressionAlgorithm> MAP = new HashMap<>();

    static {
        for (CompressionAlgorithm c : CompressionAlgorithm.values()) {
            MAP.put(c.algorithmId, c);
        }
    }

    public static CompressionAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    CompressionAlgorithm(int id) {
        this.algorithmId = id;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }
}
