/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
