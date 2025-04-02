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

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.jetbrains.annotations.NotNull;
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
        public Passphrase getPassphraseFor(@NotNull KeyIdentifier keyIdentifier) {
            long doubled = keyIdentifier.getKeyId() * 2;
            return Passphrase.fromPassword(Long.toString(doubled));
        }

        @Override
        public boolean hasPassphrase(@NotNull KeyIdentifier keyIdentifier) {
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
        assertNull(protector.getDecryptor(new KeyIdentifier(123L)));
    }

    @Test
    public void testAddPassphrase() {
        KeyIdentifier k123 = new KeyIdentifier(123L);
        Passphrase passphrase = Passphrase.fromPassword("HelloWorld");
        protector.addPassphrase(k123, passphrase);
        assertEquals(passphrase, protector.getPassphraseFor(k123));
        assertNotNull(protector.getDecryptor(k123));

        assertNull(protector.getPassphraseFor(new KeyIdentifier(999L)));
    }

    @Test
    public void testForgetPassphrase() {
        KeyIdentifier k123 = new KeyIdentifier(123L);
        Passphrase passphrase = Passphrase.fromPassword("amnesiac");
        protector.addPassphrase(k123, passphrase);
        assertEquals(passphrase, protector.getPassphraseFor(k123));
        protector.forgetPassphrase(k123);
        assertNull(protector.getPassphraseFor(k123));
    }

    @Test
    public void testAddPassphraseForKeyRing() throws PGPException {
        OpenPGPKey keys = PGPainless.getInstance().generateKey()
                .modernKeyRing("test@test.test", "Passphrase123");
        Passphrase passphrase = Passphrase.fromPassword("Passphrase123");

        protector.addPassphrase(keys, passphrase);
        Iterator<OpenPGPKey.OpenPGPSecretKey> it = keys.getSecretKeys().values().iterator();
        while (it.hasNext()) {
            OpenPGPKey.OpenPGPSecretKey key = it.next();
            assertEquals(passphrase, protector.getPassphraseFor(key));
            assertNotNull(protector.getEncryptor(key));
            assertNotNull(protector.getDecryptor(key));
        }

        long nonMatching = findNonMatchingKeyId(keys);
        assertNull(protector.getPassphraseFor(new KeyIdentifier(nonMatching)));

        protector.forgetPassphrase(keys);
        it = keys.getSecretKeys().values().iterator();
        while (it.hasNext()) {
            OpenPGPKey.OpenPGPSecretKey key = it.next();
            assertNull(protector.getPassphraseFor(key));
            assertNull(protector.getEncryptor(key.getPublicKey()));
            assertNull(protector.getDecryptor(key.getKeyIdentifier()));
        }
    }

    private static long findNonMatchingKeyId(OpenPGPCertificate cert) {
        Random random = new Random();
        long nonMatchingKeyId = 123L;
        outerloop: while (true) {
            Iterator<OpenPGPCertificate.OpenPGPComponentKey> pubKeys = cert.getKeys().iterator();
            while (pubKeys.hasNext()) {
                if (pubKeys.next().getKeyIdentifier().getKeyId() == nonMatchingKeyId) {
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
            KeyIdentifier x = new KeyIdentifier(i * 5);
            KeyIdentifier doubled = new KeyIdentifier(x.getKeyId() * 2);

            Passphrase passphrase = withCallback.getPassphraseFor(x);
            assertNotNull(passphrase);
            assertNotNull(passphrase.getChars());
            assertEquals(doubled, new KeyIdentifier(Long.parseLong(new String(passphrase.getChars()))));
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
