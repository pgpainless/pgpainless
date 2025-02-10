// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Iterator;
import java.util.Random;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

public class CachingSecretKeyRingProtectorTest {

    // Dummy passphrase callback that returns the doubled key-id as passphrase
    private final SecretKeyPassphraseProvider dummyCallback = new SecretKeyPassphraseProvider() {
        @Override
        public Passphrase getPassphraseFor(Long keyId) {
            long doubled = keyId * 2;
            return Passphrase.fromPassword(Long.toString(doubled));
        }

        @Override
        public boolean hasPassphrase(Long keyId) {
            return true;
        }
    };

    private CachingSecretKeyRingProtector protector;

    @BeforeEach
    public void resetProtectors() {
        protector = new CachingSecretKeyRingProtector();
    }

    @Test
    public void noCallbackReturnsNullForUnknownKeyId() {
        assertNull(protector.getDecryptor(123L));
        assertNull(protector.getEncryptor(123L));
    }

    @Test
    public void testAddPassphrase() {
        Passphrase passphrase = Passphrase.fromPassword("HelloWorld");
        protector.addPassphrase(123L, passphrase);
        assertEquals(passphrase, protector.getPassphraseFor(123L));
        assertNotNull(protector.getEncryptor(123L));
        assertNotNull(protector.getDecryptor(123L));

        assertNull(protector.getPassphraseFor(999L));
    }

    @Test
    public void testForgetPassphrase() {
        Passphrase passphrase = Passphrase.fromPassword("amnesiac");
        protector.addPassphrase(123L, passphrase);
        assertEquals(passphrase, protector.getPassphraseFor(123L));
        protector.forgetPassphrase(123L);
        assertNull(protector.getPassphraseFor(123L));
    }

    @Test
    public void testAddPassphraseForKeyRing() {
        PGPSecretKeyRing keys = PGPainless.generateKeyRing()
                .modernKeyRing("test@test.test", "Passphrase123")
                .getPGPSecretKeyRing();
        Passphrase passphrase = Passphrase.fromPassword("Passphrase123");

        protector.addPassphrase(keys, passphrase);
        Iterator<PGPSecretKey> it = keys.getSecretKeys();
        while (it.hasNext()) {
            PGPSecretKey key = it.next();
            assertEquals(passphrase, protector.getPassphraseFor(key));
            assertNotNull(protector.getEncryptor(key.getKeyID()));
            assertNotNull(protector.getDecryptor(key.getKeyID()));
        }

        long nonMatching = findNonMatchingKeyId(keys);
        assertNull(protector.getPassphraseFor(nonMatching));

        protector.forgetPassphrase(keys);
        it = keys.getSecretKeys();
        while (it.hasNext()) {
            PGPSecretKey key = it.next();
            assertNull(protector.getPassphraseFor(key));
            assertNull(protector.getEncryptor(key.getKeyID()));
            assertNull(protector.getDecryptor(key.getKeyID()));
        }
    }

    private static long findNonMatchingKeyId(PGPKeyRing keyRing) {
        Random random = new Random();
        long nonMatchingKeyId = 123L;
        outerloop: while (true) {
            Iterator<PGPPublicKey> pubKeys = keyRing.getPublicKeys();
            while (pubKeys.hasNext()) {
                if (pubKeys.next().getKeyID() == nonMatchingKeyId) {
                    nonMatchingKeyId = random.nextLong();
                    continue outerloop;
                }
            }
            return nonMatchingKeyId;
        }
    }

    @Test
    public void testProtectorWithCallback() {
        CachingSecretKeyRingProtector withCallback = new CachingSecretKeyRingProtector(dummyCallback);

        for (int i = -5; i <= 5; i++) {
            long x = i * 5;
            long doubled = x * 2;

            Passphrase passphrase = withCallback.getPassphraseFor(x);
            assertNotNull(passphrase);
            assertNotNull(passphrase.getChars());
            assertEquals(doubled, Long.parseLong(new String(passphrase.getChars())));
        }
    }

    @Test
    public void testAddPassphrase_collision() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        CachingSecretKeyRingProtector protector = new CachingSecretKeyRingProtector();
        protector.addPassphrase(secretKeys, TestKeys.CRYPTIE_PASSPHRASE);

        assertThrows(IllegalArgumentException.class, () ->
                protector.addPassphrase(secretKeys.getPublicKey(), Passphrase.emptyPassphrase()));

        assertThrows(IllegalArgumentException.class, () ->
                protector.addPassphrase(secretKeys, Passphrase.fromPassword("anotherPass")));
    }

    @Test
    public void testReplacePassphrase() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        CachingSecretKeyRingProtector protector = new CachingSecretKeyRingProtector();
        protector.addPassphrase(secretKeys, Passphrase.fromPassword("wrong"));
        // no throwing
        protector.replacePassphrase(secretKeys, TestKeys.CRYPTIE_PASSPHRASE);

        for (PGPSecretKey key : secretKeys) {
            UnlockSecretKey.unlockSecretKey(key, protector);
        }
    }

}
