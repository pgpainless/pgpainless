// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.HashAlgorithmTags;

/**
 * An enumeration of different hashing algorithms.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-9.4">RFC4880: Hash Algorithms</a>
 */
public enum HashAlgorithm {
    @Deprecated
    MD5        (HashAlgorithmTags.MD5, "MD5"),
    SHA1       (HashAlgorithmTags.SHA1, "SHA1"),
    RIPEMD160  (HashAlgorithmTags.RIPEMD160, "RIPEMD160"),
    SHA256     (HashAlgorithmTags.SHA256, "SHA256"),
    SHA384     (HashAlgorithmTags.SHA384, "SHA384"),
    SHA512     (HashAlgorithmTags.SHA512, "SHA512"),
    SHA224     (HashAlgorithmTags.SHA224, "SHA224"),
    ;

    private static final Map<Integer, HashAlgorithm> ID_MAP = new HashMap<>();
    private static final Map<String, HashAlgorithm> NAME_MAP = new HashMap<>();

    static {
        for (HashAlgorithm h : HashAlgorithm.values()) {
            ID_MAP.put(h.algorithmId, h);
            NAME_MAP.put(h.name, h);
        }
    }

    /**
     * Return the {@link HashAlgorithm} value that corresponds to the provided algorithm id.
     * If an invalid algorithm id was provided, null is returned.
     *
     * @param id numeric id
     * @return enum value
     */
    public static HashAlgorithm fromId(int id) {
        return ID_MAP.get(id);
    }

    /**
     * Return the {@link HashAlgorithm} value that corresponds to the provided name.
     * If an invalid algorithm name was provided, null is returned.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-9.4">RFC4880: §9.4 Hash Algorithms</a>
     * for a list of algorithms and names.
     *
     * @param name text name
     * @return enum value
     */
    public static HashAlgorithm fromName(String name) {
        return NAME_MAP.get(name);
    }

    private final int algorithmId;
    private final String name;

    HashAlgorithm(int id, String name) {
        this.algorithmId = id;
        this.name = name;
    }

    /**
     * Return the numeric algorithm id of the hash algorithm.
     *
     * @return numeric id
     */
    public int getAlgorithmId() {
        return algorithmId;
    }

    /**
     * Return the text name of the hash algorithm.
     *
     * @return text name
     */
    public String getAlgorithmName() {
        return name;
    }
}
