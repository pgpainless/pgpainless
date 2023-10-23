// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * Enumeration of possible encoding formats of the content of the literal data packet.
 *
 * See [RFC4880: Literal Data Packet](https://tools.ietf.org/html/rfc4880#section-5.9)
 */
enum class StreamEncoding(val code: Char) {

    /** The Literal packet contains binary data. */
    BINARY('b'),

    /**
     * The Literal packet contains text data, and thus may need line ends converted to local form,
     * or other text-mode changes.
     */
    TEXT('t'),

    /** Indication that the implementation believes that the literal data contains UTF-8 text. */
    UTF8('u'),

    /**
     * Early versions of PGP also defined a value of 'l' as a 'local' mode for machine-local
     * conversions. RFC 1991 [RFC1991] incorrectly stated this local mode flag as '1' (ASCII numeral
     * one). Both of these local modes are deprecated.
     */
    @Deprecated("LOCAL is deprecated.") LOCAL('l'),
    ;

    companion object {
        /**
         * Return the [StreamEncoding] corresponding to the provided code identifier. If no matching
         * encoding is found, return null.
         *
         * @param code identifier
         * @return encoding enum
         */
        @JvmStatic
        fun fromCode(code: Int): StreamEncoding? {
            return values().firstOrNull { it.code == code.toChar() }
                ?: if (code == 1) return LOCAL else null
        }

        /**
         * Return the [StreamEncoding] corresponding to the provided code identifier. If no matching
         * encoding is found, throw a [NoSuchElementException].
         *
         * @param code identifier
         * @return encoding enum
         * @throws NoSuchElementException in case of an unmatched identifier
         */
        @JvmStatic
        fun requireFromCode(code: Int): StreamEncoding {
            return fromCode(code)
                ?: throw NoSuchElementException("No StreamEncoding found for code $code")
        }
    }
}
