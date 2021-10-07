// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPLiteralData;

/**
 * Enumeration of possible encoding formats of the content of the literal data packet.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.9">RFC4880: Literal Data Packet</a>
 */
public enum StreamEncoding {

    /**
     * The Literal packet contains binary data.
     */
    BINARY(PGPLiteralData.BINARY),

    /**
     * The Literal packet contains text data, and thus may need line ends converted to local form, or other
     * text-mode changes.
     */
    TEXT(PGPLiteralData.TEXT),

    /**
     * Indication that the implementation believes that the literal data contains UTF-8 text.
     */
    UTF8(PGPLiteralData.UTF8),

    /**
     * Early versions of PGP also defined a value of 'l' as a 'local' mode for machine-local conversions.
     * RFC 1991 [RFC1991] incorrectly stated this local mode flag as '1' (ASCII numeral one).
     * Both of these local modes are deprecated.
     */
    @Deprecated
    LOCAL('l'),
    ;

    private final char code;

    private static final Map<Character, StreamEncoding> MAP = new ConcurrentHashMap<>();
    static {
        for (StreamEncoding f : StreamEncoding.values()) {
            MAP.put(f.code, f);
        }
        // RFC 1991 [RFC1991] incorrectly stated local mode flag as '1', see doc of LOCAL.
        MAP.put('1', LOCAL);
    }

    StreamEncoding(char code) {
        this.code = code;
    }

    /**
     * Return the code identifier of the encoding.
     *
     * @return identifier
     */
    public char getCode() {
        return code;
    }

    /**
     * Return the {@link StreamEncoding} corresponding to the provided code identifier.
     *
     * @param code identifier
     * @return encoding enum
     */
    public static StreamEncoding fromCode(int code) {
        return MAP.get((char) code);
    }
}
