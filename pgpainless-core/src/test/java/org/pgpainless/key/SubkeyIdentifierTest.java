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
package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SubkeyIdentifierTest {

    private static PGPPublicKeyRing CERT;
    private static final OpenPgpV4Fingerprint PRIMARY_FP = new OpenPgpV4Fingerprint("4F665C4DC2C4660BC6425E415736E6931ACF370C");
    private static final OpenPgpV4Fingerprint SUBKEY_FP = new OpenPgpV4Fingerprint("F73FDE6439ABE210B1AF4EDD273EF7A0C749807B");

    @BeforeAll
    public static void setup() throws IOException {
        CERT = TestKeys.getEmilPublicKeyRing();
    }

    @Test
    public void fromKeyRing() {
        SubkeyIdentifier identifier = new SubkeyIdentifier(CERT);

        assertEquals(PRIMARY_FP, identifier.getPrimaryKeyFingerprint());
        assertEquals(PRIMARY_FP, identifier.getSubkeyFingerprint());
        assertEquals(PRIMARY_FP, identifier.getFingerprint());
    }

    @Test
    public void fromKeyRingAndSubkeyId() {
        SubkeyIdentifier identifier = new SubkeyIdentifier(CERT, SUBKEY_FP);

        assertEquals(PRIMARY_FP, identifier.getPrimaryKeyFingerprint());
        assertEquals(SUBKEY_FP, identifier.getSubkeyFingerprint());
        assertEquals(SUBKEY_FP, identifier.getFingerprint());
    }

    @Test
    public void fromFingerprints() {
        SubkeyIdentifier identifier = new SubkeyIdentifier(PRIMARY_FP, SUBKEY_FP);

        assertEquals(PRIMARY_FP, identifier.getPrimaryKeyFingerprint());
        assertEquals(SUBKEY_FP, identifier.getSubkeyFingerprint());
        assertEquals(SUBKEY_FP, identifier.getFingerprint());
    }

    @Test
    public void fromFingerprint() {
        SubkeyIdentifier identifier = new SubkeyIdentifier(PRIMARY_FP);

        assertEquals(PRIMARY_FP, identifier.getFingerprint());
        assertEquals(PRIMARY_FP, identifier.getSubkeyFingerprint());
        assertEquals(PRIMARY_FP, identifier.getPrimaryKeyFingerprint());
    }

    @Test
    public void testGetKeyIds() {
        SubkeyIdentifier identifier = new SubkeyIdentifier(CERT, SUBKEY_FP);
        assertEquals(PRIMARY_FP.getKeyId(), identifier.getPrimaryKeyId());
        assertEquals(SUBKEY_FP.getKeyId(), identifier.getKeyId());
        assertEquals(SUBKEY_FP.getKeyId(), identifier.getSubkeyId());
    }

    @Test
    public void toStringTest() {
        SubkeyIdentifier identifier = new SubkeyIdentifier(CERT, SUBKEY_FP);

        assertEquals("F73FDE6439ABE210B1AF4EDD273EF7A0C749807B 4F665C4DC2C4660BC6425E415736E6931ACF370C", identifier.toString());
    }

    @Test
    public void testEquals() {
        SubkeyIdentifier id1 = new SubkeyIdentifier(CERT, SUBKEY_FP);
        SubkeyIdentifier id2 = new SubkeyIdentifier(PRIMARY_FP, SUBKEY_FP);

        assertEquals(id1, id1);
        assertEquals(id1, id2);

        assertEquals(id1.hashCode(), id2.hashCode());
    }

    @Test
    public void testNotEquals() {
        SubkeyIdentifier id1 = new SubkeyIdentifier(CERT, SUBKEY_FP);
        SubkeyIdentifier id2 = new SubkeyIdentifier(PRIMARY_FP);
        SubkeyIdentifier id3 = new SubkeyIdentifier(SUBKEY_FP);

        assertNotEquals(id1, id2);
        assertNotEquals(id2, id3);
        assertNotEquals(id1, id3);

        assertNotEquals(id1, PRIMARY_FP);
        assertNotEquals(id1, null);
    }
}
