// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class KeyIdUtilTest {

    @Test
    public void testParsing() {
        String longKeyId = "b1bd1f049ec87f3d"; // we parse from lowercase, but formatting will produce uppercase
        long asLong = KeyIdUtil.fromLongKeyId(longKeyId);
        assertEquals(-5639317053693722819L, asLong);
        assertEquals(longKeyId.toUpperCase(), KeyIdUtil.formatKeyId(-5639317053693722819L));
    }

    @Test
    public void testParsingLowerAndUppercase() {
        long fromLower = KeyIdUtil.fromLongKeyId("f5ffdf6d71dd5789");
        assertEquals(-720611754201229431L, fromLower);
        long fromUpper = KeyIdUtil.fromLongKeyId("F5FFDF6D71DD5789");
        assertEquals(-720611754201229431L, fromUpper);
    }

    @Test
    public void formatLowerAsUpper() {
        assertEquals("5F04ACF44FD822B1", KeyIdUtil.formatKeyId(KeyIdUtil.fromLongKeyId("5f04acf44fd822b1")));
    }

    @Test
    public void testParsing0() {
        long asLong = 0L;
        String formatted = KeyIdUtil.formatKeyId(asLong);
        assertEquals("0000000000000000", formatted);
        assertEquals(asLong, KeyIdUtil.fromLongKeyId("0000000000000000"));
    }
}
