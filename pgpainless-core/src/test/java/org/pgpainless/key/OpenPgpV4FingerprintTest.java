// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.Test;


public class OpenPgpV4FingerprintTest {

    @Test
    public void fpTooShort() {
        String fp = "484f57414c495645"; // Asking Mark
        assertThrows(IllegalArgumentException.class, () -> new OpenPgpV4Fingerprint(fp));
    }

    @Test
    public void invalidHexTest() {
        String fp = "UNFORTUNATELYTHISISNOVALIDHEXADECIMALDOH";
        assertThrows(IllegalArgumentException.class, () -> new OpenPgpV4Fingerprint(fp));
    }

    @Test
    public void validFingerprintTest() {
        String fp = "4A4F48414E4E53454E2049532041204E45524421";
        OpenPgpV4Fingerprint finger = new OpenPgpV4Fingerprint(fp);
        assertEquals(fp, finger.toString());
        assertEquals(fp.length(), finger.length());
        for (int i = 0; i < finger.length(); i++) {
            assertEquals(fp.charAt(i), finger.charAt(i));
        }
        assertEquals("4A4F", finger.subSequence(0, 4));
    }

    @Test
    public void convertsToUpperCaseTest() {
        String fp = "444f4e5420552048415645204120484f4242593f";
        OpenPgpV4Fingerprint finger = new OpenPgpV4Fingerprint(fp);
        assertEquals("444F4E5420552048415645204120484F4242593F", finger.toString());
    }

    @Test
    public void equalsOtherFingerprintTest() {
        OpenPgpV4Fingerprint finger = new OpenPgpV4Fingerprint("5448452043414b452049532041204c4945212121");
        assertEquals(finger, new OpenPgpV4Fingerprint("5448452043414B452049532041204C4945212121"));
        assertEquals(0, finger.compareTo(new OpenPgpV4Fingerprint("5448452043414B452049532041204C4945212121")));
        assertNotEquals(finger, new OpenPgpV4Fingerprint("0000000000000000000000000000000000000000"));
        assertNotEquals(finger, null);
        assertNotEquals(finger, new Object());
    }

    @Test
    public void assertFingerprintGetKeyIdEqualsKeyId() throws IOException {
        PGPPublicKey key = TestKeys.getJulietPublicKeyRing().getPublicKey();
        long keyId = key.getKeyID();

        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(key);
        assertEquals(keyId, fingerprint.getKeyId());
    }

    @Test
    public void testToUri() {
        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint("5448452043414B452049532041204C4945212121");

        URI uri = fingerprint.toUri();
        assertEquals("openpgp4fpr:5448452043414B452049532041204C4945212121", uri.toString());

        OpenPgpV4Fingerprint parsed = OpenPgpV4Fingerprint.fromUri(uri);
        assertEquals(fingerprint, parsed);
    }

    @Test
    public void testFromUriThrowsIfWrongScheme() throws URISyntaxException {
        URI uri = new URI(null, "5448452043414B452049532041204C4945212121", null);
        assertThrows(IllegalArgumentException.class, () -> OpenPgpV4Fingerprint.fromUri(uri));
    }

    @Test
    public void testFromPrettyPrinted() {
        String prettyPrint = "C94B 884B 9A56 7B1C FB23  6999 7DC5 BDAC BBDF BF87";
        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(prettyPrint);
        assertEquals(prettyPrint, fingerprint.prettyPrint());
    }

    @Test
    public void testParse() {
        String prettyPrint = "C94B 884B 9A56 7B1C FB23  6999 7DC5 BDAC BBDF BF87";
        OpenPgpFingerprint parsed = OpenPgpFingerprint.parse(prettyPrint);

        assertTrue(parsed instanceof OpenPgpV4Fingerprint);
        OpenPgpV4Fingerprint v4fp = (OpenPgpV4Fingerprint) parsed;
        assertEquals(prettyPrint, v4fp.prettyPrint());
    }
}
