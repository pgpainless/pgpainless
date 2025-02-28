// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * An enumeration of different hashing algorithms.
 *
 * See [RFC4880: Hash Algorithms](https://tools.ietf.org/html/rfc4880#section-9.4)
 */
enum class HashAlgorithm(val algorithmId: Int, val algorithmName: String) {

    // 0 is reserved
    @Deprecated("MD5 is deprecated") MD5(1, "MD5"),
    SHA1(2, "SHA1"),
    RIPEMD160(3, "RIPEMD160"),
    // 4 - 7 are reserved
    SHA256(8, "SHA256"),
    SHA384(9, "SHA384"),
    SHA512(10, "SHA512"),
    SHA224(11, "SHA224"),
    SHA3_256(12, "SHA3-256"),
    // 13 is reserved
    SHA3_512(14, "SHA3-512"),
    // 100 - 110 are private / experimental
    ;

    companion object {
        /**
         * Return the [HashAlgorithm] value that corresponds to the provided algorithm id. If an
         * invalid algorithm id was provided, null is returned.
         *
         * @param id numeric id
         * @return enum value
         */
        @JvmStatic
        fun fromId(id: Int): HashAlgorithm? {
            return values().firstOrNull { h -> h.algorithmId == id }
        }

        /**
         * Return the [HashAlgorithm] value that corresponds to the provided algorithm id. If an
         * invalid algorithm id was provided, throw a [NoSuchElementException].
         *
         * @param id algorithm id
         * @return enum value
         * @throws NoSuchElementException in case of an unknown algorithm id
         */
        @JvmStatic
        fun requireFromId(id: Int): HashAlgorithm {
            return fromId(id) ?: throw NoSuchElementException("No HashAlgorithm found for id $id")
        }

        /**
         * Return the [HashAlgorithm] value that corresponds to the provided name. If an invalid
         * algorithm name was provided, null is returned.
         *
         * See
         * [RFC4880: §9.4 Hash Algorithms](https://datatracker.ietf.org/doc/html/rfc4880#section-9.4)
         * for a list of algorithms and names.
         *
         * @param name text name
         * @return enum value or null
         */
        @JvmStatic
        fun fromName(name: String): HashAlgorithm? {
            return name.uppercase().let { algoName ->
                // find value where it.algorithmName == ALGO-NAME
                values().firstOrNull { it.algorithmName == algoName }
                // else, find value where it.algorithmName == ALGONAME
                ?: values().firstOrNull { it.algorithmName == algoName.replace("-", "") }
            }
        }
    }
}
