// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.util.TestUtils;

public class TestKeysTest {

    private final PGPSecretKeyRing julietSecRing;
    private final PGPSecretKeyRing romeoSecRing;
    private final PGPSecretKeyRing emilSecRing;
    private final PGPPublicKeyRing julietPubRing;
    private final PGPPublicKeyRing romeoPubRing;
    private final PGPPublicKeyRing emilPubRing;

    public TestKeysTest() throws IOException, PGPException {
        this.julietSecRing = TestKeys.getJulietSecretKeyRing();
        this.romeoSecRing = TestKeys.getRomeoSecretKeyRing();
        this.emilSecRing = TestKeys.getEmilSecretKeyRing();
        this.julietPubRing = TestKeys.getJulietPublicKeyRing();
        this.romeoPubRing = TestKeys.getRomeoPublicKeyRing();
        this.emilPubRing = TestKeys.getEmilPublicKeyRing();
    }

    @Test
    public void assertJulietsPublicKeyIsSameInPubRingAndSecRing() throws IOException {
        assertArrayEquals(julietSecRing.getPublicKey().getEncoded(), julietPubRing.getPublicKey().getEncoded());
    }

    @Test
    public void assertJulietsKeysIdEquals() {
        assertEquals(TestKeys.JULIET_KEY_ID, julietSecRing.getSecretKey().getKeyID());
        assertEquals(TestKeys.JULIET_KEY_ID, julietSecRing.getPublicKey().getKeyID());
        assertEquals(TestKeys.JULIET_KEY_ID, julietPubRing.getPublicKey().getKeyID());
    }

    @Test
    public void assertJulietsKeyUIDEquals() {
        assertEquals(TestKeys.JULIET_UID, julietSecRing.getPublicKey().getUserIDs().next());
        assertEquals(1, TestUtils.getNumberOfItemsInIterator(julietSecRing.getPublicKey().getUserIDs()));
    }

    @Test
    public void assertJulietsKeyRingFingerprintMatches() {
        assertEquals(TestKeys.JULIET_FINGERPRINT, new OpenPgpV4Fingerprint(julietSecRing));
    }

    @Test
    public void assertJulietsPublicKeyFingerprintMatchesHerSecretKeyFingerprint() {
        assertEquals(new OpenPgpV4Fingerprint(julietSecRing.getPublicKey()), new OpenPgpV4Fingerprint(julietSecRing.getSecretKey()));
    }

    @Test
    public void assertJulietsFingerprintGetKeyIdMatches() {
        assertEquals(TestKeys.JULIET_KEY_ID, TestKeys.JULIET_FINGERPRINT.getKeyId(),
                "calling getKeyId() on juliet's fingerprint must return her key id.");
    }

    @Test
    public void assertRomeosPublicKeyIsSameInPubRingAndSecRing() throws IOException {
        assertArrayEquals(romeoSecRing.getPublicKey().getEncoded(), romeoPubRing.getPublicKey().getEncoded());
    }

    @Test
    public void assertRomeosKeyIdEquals() {
        assertEquals(TestKeys.ROMEO_KEY_ID, romeoSecRing.getSecretKey().getKeyID(),
                "Key ID of Romeo's secret key must match his key id.");
    }

    @Test
    public void assertRomeosKeyUIDMatches() {
        assertEquals(TestKeys.ROMEO_UID, romeoSecRing.getPublicKey().getUserIDs().next());
    }

    @Test
    public void assertRomeosKeyRingFingerprintMatches() {
        assertEquals(TestKeys.ROMEO_FINGERPRINT, new OpenPgpV4Fingerprint(romeoSecRing));
    }

    @Test
    public void assertRomeosPublicKeyFingerprintMatchesHisSecretKeyFingerprint() {
        assertEquals(new OpenPgpV4Fingerprint(romeoSecRing.getPublicKey()), new OpenPgpV4Fingerprint(romeoSecRing.getSecretKey()));
    }

    @Test
    public void assertRomesKeysFingerprintMatches() {
        assertEquals(TestKeys.ROMEO_KEY_ID, TestKeys.ROMEO_FINGERPRINT.getKeyId());
    }

    @Test
    public void assertRomeosSecretKeyRingHasSamePublicKeyId() throws IOException {
        PGPPublicKeyRing julietsPublicKeys = TestKeys.getJulietPublicKeyRing();
        assertEquals(julietSecRing.getPublicKey().getKeyID(), julietsPublicKeys.getPublicKey().getKeyID());
    }

    @Test
    public void assertEmilsPublicKeyIsSameInPubRingAndSecRing() throws IOException {
        assertArrayEquals(emilSecRing.getPublicKey().getEncoded(), emilPubRing.getPublicKey().getEncoded());
    }

    @Test
    public void assertEmilsKeysIdEquals() {
        assertEquals(TestKeys.EMIL_KEY_ID, emilSecRing.getSecretKey().getKeyID());
        assertEquals(TestKeys.EMIL_KEY_ID, emilSecRing.getPublicKey().getKeyID());
        assertEquals(TestKeys.EMIL_KEY_ID, emilPubRing.getPublicKey().getKeyID());
    }

    @Test
    public void assertEmilsKeyUIDEquals() {
        assertEquals(TestKeys.EMIL_UID, emilSecRing.getPublicKey().getUserIDs().next());
        assertEquals(1, TestUtils.getNumberOfItemsInIterator(emilSecRing.getPublicKey().getUserIDs()));
    }

    @Test
    public void assertEmilsKeyRingFingerprintMatches() {
        assertEquals(TestKeys.EMIL_FINGERPRINT, new OpenPgpV4Fingerprint(emilSecRing));
    }

    @Test
    public void assertEmilsPublicKeyFingerprintMatchesHerSecretKeyFingerprint() {
        assertEquals(new OpenPgpV4Fingerprint(emilSecRing.getPublicKey()), new OpenPgpV4Fingerprint(emilSecRing.getSecretKey()));
    }

    @Test
    public void assertEmilsFingerprintGetKeyIdMatches() {
        assertEquals(TestKeys.EMIL_KEY_ID, TestKeys.EMIL_FINGERPRINT.getKeyId(),
                "calling getKeyId() on emil's fingerprint must return her key id.");
    }
}
