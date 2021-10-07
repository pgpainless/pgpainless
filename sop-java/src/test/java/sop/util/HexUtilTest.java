// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.Charset;

import org.junit.jupiter.api.Test;

/**
 * Test using some test vectors from RFC4648.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4648#section-10">RFC-4648 §10: Test Vectors</a>
 */
public class HexUtilTest {

    private static final Charset ASCII = Charset.forName("US-ASCII");

    @Test
    public void emptyHexEncodeTest() {
        assertHexEquals("", "");
    }

    @Test
    public void encodeF() {
        assertHexEquals("66", "f");
    }

    @Test
    public void encodeFo() {
        assertHexEquals("666F", "fo");
    }

    @Test
    public void encodeFoo() {
        assertHexEquals("666F6F", "foo");
    }

    @Test
    public void encodeFoob() {
        assertHexEquals("666F6F62", "foob");
    }

    @Test
    public void encodeFooba() {
        assertHexEquals("666F6F6261", "fooba");
    }

    @Test
    public void encodeFoobar() {
        assertHexEquals("666F6F626172", "foobar");
    }

    private void assertHexEquals(String hex, String ascii) {
        assertEquals(hex, HexUtil.bytesToHex(ascii.getBytes(ASCII)));
        assertArrayEquals(ascii.getBytes(ASCII), HexUtil.hexToBytes(hex));
    }
}
