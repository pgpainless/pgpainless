// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenPgpV5FingerprintTest {

    @Test
    public void testFingerprintFormatting() {
        String pretty = "76543210 ABCDEFAB 01AB23CD 1C0FFEE1  1EEFF0C1 DC32BA10 BAFEDCBA 01234567";
        String fp = pretty.replace(" ", "");

        OpenPgpV5Fingerprint fingerprint = new OpenPgpV5Fingerprint(fp);
        assertEquals(fp, fingerprint.toString());
        assertEquals(pretty, fingerprint.prettyPrint());

        long id = fingerprint.getKeyId();
        assertEquals("76543210abcdefab", Long.toHexString(id));
    }

    @Test
    public void testParse() {
        String prettyPrint = "76543210 ABCDEFAB 01AB23CD 1C0FFEE1  1EEFF0C1 DC32BA10 BAFEDCBA 01234567";
        OpenPgpFingerprint parsed = OpenPgpFingerprint.parse(prettyPrint);

        assertTrue(parsed instanceof OpenPgpV5Fingerprint);
        OpenPgpV5Fingerprint v5fp = (OpenPgpV5Fingerprint) parsed;
        assertEquals(prettyPrint, v5fp.prettyPrint());
        assertEquals(5, v5fp.getVersion());
    }

    @Test
    public void testParseFromBinary() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        byte[] binary = Hex.decode(hex);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.parseFromBinary(binary);
        assertTrue(fingerprint instanceof OpenPgpV5Fingerprint);
        assertEquals(hex, fingerprint.toString());

        OpenPgpV5Fingerprint constructed = new OpenPgpV5Fingerprint(binary);
        assertEquals(fingerprint, constructed);
    }

    @Test
    public void testParseFromBinary_leadingZeros() {
        String hex = "000000000000000001AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        byte[] binary = Hex.decode(hex);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.parseFromBinary(binary);
        assertTrue(fingerprint instanceof OpenPgpV5Fingerprint);
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void testParseFromBinary_trailingZeros() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA100000000000000000";
        byte[] binary = Hex.decode(hex);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.parseFromBinary(binary);
        assertTrue(fingerprint instanceof OpenPgpV5Fingerprint);
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void testParseFromBinary_wrongLength() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA012345"; // missing 2 digits
        byte[] binary = Hex.decode(hex);

        assertThrows(IllegalArgumentException.class, () -> OpenPgpFingerprint.parseFromBinary(binary));
    }

    @Test
    public void equalsTest() {
        String prettyPrint = "76543210 ABCDEFAB 01AB23CD 1C0FFEE1  1EEFF0C1 DC32BA10 BAFEDCBA 01234567";
        OpenPgpFingerprint parsed = OpenPgpFingerprint.parse(prettyPrint);

        assertNotEquals(parsed, null);
        assertNotEquals(parsed, new Object());
        assertEquals(parsed, parsed.toString());

        OpenPgpFingerprint parsed2 = new OpenPgpV5Fingerprint(prettyPrint);
        assertEquals(parsed.hashCode(), parsed2.hashCode());
        assertEquals(0, parsed.compareTo(parsed2));
    }
}
