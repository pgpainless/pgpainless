// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * Enumeration of possible symmetric encryption algorithms.
 *
 * See [RFC4880: Symmetric-Key Algorithms](https://tools.ietf.org/html/rfc4880#section-9.2)
 */
enum class SymmetricKeyAlgorithm(val algorithmId: Int) {

    /**
     * Plaintext or unencrypted data.
     */
    NULL            (0),

    /**
     * IDEA is deprecated.
     * @deprecated use a different algorithm.
     */
    @Deprecated("IDEA is deprecated.")
    IDEA            (1),

    /**
     * TripleDES (DES-EDE - 168 bit key derived from 192).
     */
    TRIPLE_DES      (2),

    /**
     * CAST5 (128-bit key, as per RFC2144).
     */
    CAST5           (3),

    /**
     * Blowfish (128-bit key, 16 rounds).
     */
    BLOWFISH        (4),

    /**
     * Reserved in RFC4880.
     * SAFER-SK128 (13 rounds)
     */
    SAFER           (5),

    /**
     * Reserved in RFC4880.
     * Reserved for DES/SK
     */
    DES             (6),

    /**
     * AES with 128-bit key.
     */
    AES_128         (7),

    /**
     * AES with 192-bit key.
     */
    AES_192         (8),

    /**
     * AES with 256-bit key.
     */
    AES_256         (9),

    /**
     * Twofish with 256-bit key.
     */
    TWOFISH         (10),

    /**
     * Reserved for Camellia with 128-bit key.
     */
    CAMELLIA_128    (11),

    /**
     * Reserved for Camellia with 192-bit key.
     */
    CAMELLIA_192    (12),

    /**
     * Reserved for Camellia with 256-bit key.
     */
    CAMELLIA_256    (13),
    ;

    companion object {

        /**
         * Return the [SymmetricKeyAlgorithm] enum that corresponds to the provided numeric id.
         * If an invalid id is provided, null is returned.
         *
         * @param id numeric algorithm id
         * @return symmetric key algorithm enum
         */
        @JvmStatic
        fun fromId(id: Int): SymmetricKeyAlgorithm? {
            return values().firstOrNull { 
                it.algorithmId == id
            }
        }

        /**
         * Return the [SymmetricKeyAlgorithm] enum that corresponds to the provided numeric id.
         * If an invalid id is provided, throw a [NoSuchElementException].
         *
         * @param id numeric algorithm id
         * @return symmetric key algorithm enum
         *
         * @throws NoSuchElementException if an unmatched id is provided
         */
        @JvmStatic
        fun requireFromId(id: Int): SymmetricKeyAlgorithm {
            return fromId(id) ?:
            throw NoSuchElementException("No SymmetricKeyAlgorithm found for id $id")
        }
    }
}