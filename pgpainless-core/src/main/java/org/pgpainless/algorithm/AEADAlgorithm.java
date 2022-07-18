// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * List of AEAD algorithms defined in crypto-refresh-06.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-06.html#name-aead-algorithms">
 *     Crypto-Refresh-06 §9.6 - AEAD Algorithms</a>
 */
public enum AEADAlgorithm {

    EAX(1, 16, 16),
    OCB(2, 15, 16),
    GCM(3, 12, 16),
    ;

    private final int algorithmId;
    private final int ivLength;
    private final int tagLength;

    private static final Map<Integer, AEADAlgorithm> MAP = new HashMap<>();

    static {
        for (AEADAlgorithm h : AEADAlgorithm.values()) {
            MAP.put(h.algorithmId, h);
        }
    }

    AEADAlgorithm(int id, int ivLength, int tagLength) {
        this.algorithmId = id;
        this.ivLength = ivLength;
        this.tagLength = tagLength;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }

    /**
     * Return the length (in octets) of the IV.
     *
     * @return iv length
     */
    public int getIvLength() {
        return ivLength;
    }

    /**
     * Return the length (in octets) of the authentication tag.
     *
     * @return tag length
     */
    public int getTagLength() {
        return tagLength;
    }

    /**
     * Return the {@link AEADAlgorithm} value that corresponds to the provided algorithm id.
     * If an invalid algorithm id was provided, null is returned.
     *
     * @param id numeric id
     * @return enum value
     */
    @Nullable
    public static AEADAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    /**
     * Return the  {@link AEADAlgorithm} value that corresponds to the provided algorithm id.
     * If an invalid algorithm id was provided, throw a {@link NoSuchElementException}.
     *
     * @param id algorithm id
     * @return enum value
     * @throws NoSuchElementException in case of an unknown algorithm id
     */
    @Nonnull
    public static AEADAlgorithm requireFromId(int id) {
        AEADAlgorithm algorithm = fromId(id);
        if (algorithm == null) {
            throw new NoSuchElementException("No AEADAlgorithm found for id " + id);
        }
        return algorithm;
    }

}
