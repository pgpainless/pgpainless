// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * Enumeration of possible compression algorithms.
 *
 * See also [RFC4880 - Compression Algorithm Tags](https://tools.ietf.org/html/rfc4880#section-9.3)
 */
enum class CompressionAlgorithm(val algorithmId: Int) {

    UNCOMPRESSED(0),
    ZIP(1),
    ZLIB(2),
    BZIP2(3),
    ;

    companion object {

        /**
         * Return the [CompressionAlgorithm] value that corresponds to the provided numerical id. If
         * an invalid id is provided, null is returned.
         *
         * @param id id
         * @return compression algorithm
         */
        @JvmStatic
        fun fromId(id: Int): CompressionAlgorithm? {
            return values().firstOrNull { c -> c.algorithmId == id }
        }

        /**
         * Return the [CompressionAlgorithm] value that corresponds to the provided numerical id. If
         * an invalid id is provided, throw an [NoSuchElementException].
         *
         * @param id id
         * @return compression algorithm
         * @throws NoSuchElementException in case of an unmapped id
         */
        @JvmStatic
        fun requireFromId(id: Int): CompressionAlgorithm {
            return fromId(id)
                ?: throw NoSuchElementException("No CompressionAlgorithm found for id $id")
        }
    }
}
