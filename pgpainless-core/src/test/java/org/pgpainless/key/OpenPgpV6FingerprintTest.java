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
import org.pgpainless.PGPainless;

import java.io.IOException;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        assertInstanceOf(OpenPgpV6Fingerprint.class, fingerprint);
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

    @Test
    public void fromSampleV6Certificate() throws IOException {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n" +
                "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n" +
                "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n" +
                "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n" +
                "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n" +
                "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n" +
                "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n" +
                "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n" +
                "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(CERT);
        assertNotNull(cert);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(cert);
        assertEquals(6, fingerprint.getVersion());
        assertEquals("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", fingerprint.toString());

        Iterator<PGPPublicKey> keys = cert.getPublicKeys();
        fingerprint = OpenPgpFingerprint.of(keys.next());
        assertEquals(6, fingerprint.getVersion());
        assertEquals("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9",
                fingerprint.toString());

        fingerprint = OpenPgpFingerprint.of(keys.next());
        assertEquals(6, fingerprint.getVersion());
        assertEquals("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885",
                fingerprint.toString());
    }

    @Test
    public void fromSampleV6SecretKey() throws IOException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
                "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
                "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
                "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
                "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
                "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
                "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
                "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
                "k0mXubZvyl4GBg==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        assertNotNull(secretKeys);

        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(secretKeys);
        assertEquals(6, fingerprint.getVersion());
        assertEquals("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", fingerprint.toString());

        Iterator<PGPSecretKey> keys = secretKeys.getSecretKeys();
        fingerprint = OpenPgpFingerprint.of(keys.next());
        assertEquals(6, fingerprint.getVersion());
        assertEquals("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9",
                fingerprint.toString());

        fingerprint = OpenPgpFingerprint.of(keys.next());
        assertEquals(6, fingerprint.getVersion());
        assertEquals("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885",
                fingerprint.toString());
    }

    private PGPPublicKey getMockedPublicKey(String hex) {
        byte[] binary = Hex.decode(hex);

        PGPPublicKey mocked = mock(PGPPublicKey.class);
        when(mocked.getVersion()).thenReturn(6);
        when(mocked.getFingerprint()).thenReturn(binary);
        return mocked;
    }
}
