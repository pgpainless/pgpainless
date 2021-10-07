// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

/**
 * Enumeration of possible compression algorithms.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-9.3">RFC4880: Compression Algorithm Tags</a>
 */
public enum CompressionAlgorithm {

    UNCOMPRESSED   (CompressionAlgorithmTags.UNCOMPRESSED),
    ZIP            (CompressionAlgorithmTags.ZIP),
    ZLIB           (CompressionAlgorithmTags.ZLIB),
    BZIP2          (CompressionAlgorithmTags.BZIP2),
    ;

    private static final Map<Integer, CompressionAlgorithm> MAP = new ConcurrentHashMap<>();

    static {
        for (CompressionAlgorithm c : CompressionAlgorithm.values()) {
            MAP.put(c.algorithmId, c);
        }
    }

    /**
     * Return the {@link CompressionAlgorithm} value that corresponds to the provided numerical id.
     * If an invalid id is provided, null is returned.
     *
     * @param id id
     * @return compression algorithm
     */
    public static CompressionAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    CompressionAlgorithm(int id) {
        this.algorithmId = id;
    }

    /**
     * Return the numerical algorithm tag corresponding to this compression algorithm.
     * @return id
     */
    public int getAlgorithmId() {
        return algorithmId;
    }
}
