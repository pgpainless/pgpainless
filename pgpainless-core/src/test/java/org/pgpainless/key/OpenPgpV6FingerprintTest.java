// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpenPgpV6FingerprintTest {

    @Test
    public void testFingerprintFormatting() {
        String pretty = "76543210 ABCDEFAB 01AB23CD 1C0FFEE1  1EEFF0C1 DC32BA10 BAFEDCBA 01234567";
        String fp = pretty.replace(" ", "");

        OpenPgpV6Fingerprint fingerprint = new OpenPgpV6Fingerprint(fp);
        assertEquals(fp, fingerprint.toString());
        assertEquals(pretty, fingerprint.prettyPrint());
        assertEquals(6, fingerprint.getVersion());

        long id = fingerprint.getKeyId();
        assertEquals("76543210abcdefab", Long.toHexString(id));
    }

    @Test
    public void testParseFromBinary_leadingZeros() {
        String hex = "000000000000000001AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        byte[] binary = Hex.decode(hex);

        OpenPgpFingerprint fingerprint = new OpenPgpV6Fingerprint(binary);
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void testParseFromBinary_trailingZeros() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA100000000000000000";
        byte[] binary = Hex.decode(hex);

        OpenPgpFingerprint fingerprint = new OpenPgpV6Fingerprint(binary);
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void testParseFromBinary_wrongLength() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA012345"; // missing 2 digits
        byte[] binary = Hex.decode(hex);

        assertThrows(IllegalArgumentException.class, () -> new OpenPgpV6Fingerprint(binary));
    }

    @Test
    public void equalsTest() {
        String prettyPrint = "76543210 ABCDEFAB 01AB23CD 1C0FFEE1  1EEFF0C1 DC32BA10 BAFEDCBA 01234567";
        OpenPgpFingerprint parsed = new OpenPgpV6Fingerprint(prettyPrint);

        assertNotEquals(parsed, null);
        assertNotEquals(parsed, new Object());
        assertEquals(parsed, parsed.toString());

        OpenPgpFingerprint parsed2 = new OpenPgpV6Fingerprint(prettyPrint);
        assertEquals(parsed.hashCode(), parsed2.hashCode());
        assertEquals(0, parsed.compareTo(parsed2));
    }

    @Test
    public void constructFromMockedPublicKey() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        PGPPublicKey publicKey = getMockedPublicKey(hex);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(publicKey);
        assertTrue(fingerprint instanceof OpenPgpV6Fingerprint);
        assertEquals(6, fingerprint.getVersion());
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void constructFromMockedSecretKey() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        PGPPublicKey publicKey = getMockedPublicKey(hex);
        PGPSecretKey secretKey = mock(PGPSecretKey.class);
        when(secretKey.getPublicKey()).thenReturn(publicKey);

        OpenPgpFingerprint fingerprint = new OpenPgpV6Fingerprint(secretKey);
        assertEquals(6, fingerprint.getVersion());
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void constructFromMockedPublicKeyRing() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        PGPPublicKey publicKey = getMockedPublicKey(hex);
        PGPPublicKeyRing publicKeys = mock(PGPPublicKeyRing.class);
        when(publicKeys.getPublicKey()).thenReturn(publicKey);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(publicKeys);
        assertEquals(6, fingerprint.getVersion());
        assertEquals(hex, fingerprint.toString());

        fingerprint = new OpenPgpV6Fingerprint(publicKeys);
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void constructFromMockedSecretKeyRing() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        PGPPublicKey publicKey = getMockedPublicKey(hex);
        PGPSecretKeyRing secretKeys = mock(PGPSecretKeyRing.class);
        when(secretKeys.getPublicKey()).thenReturn(publicKey);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(secretKeys);
        assertEquals(6, fingerprint.getVersion());
        assertEquals(hex, fingerprint.toString());

        fingerprint = new OpenPgpV6Fingerprint(secretKeys);
        assertEquals(hex, fingerprint.toString());
    }

    @Test
    public void constructFromMockedKeyRing() {
        String hex = "76543210ABCDEFAB01AB23CD1C0FFEE11EEFF0C1DC32BA10BAFEDCBA01234567";
        PGPPublicKey publicKey = getMockedPublicKey(hex);
        PGPKeyRing keys = mock(PGPKeyRing.class);
        when(keys.getPublicKey()).thenReturn(publicKey);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(keys);
        assertEquals(6, fingerprint.getVersion());
        assertEquals(hex, fingerprint.toString());

        fingerprint = new OpenPgpV6Fingerprint(keys);
        assertEquals(hex, fingerprint.toString());
    }

    private PGPPublicKey getMockedPublicKey(String hex) {
        byte[] binary = Hex.decode(hex);

        PGPPublicKey mocked = mock(PGPPublicKey.class);
        when(mocked.getVersion()).thenReturn(6);
        when(mocked.getFingerprint()).thenReturn(binary);
        return mocked;
    }
}
