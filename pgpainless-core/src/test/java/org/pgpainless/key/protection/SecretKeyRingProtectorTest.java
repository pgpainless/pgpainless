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
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class SecretKeyRingProtectorTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testUnlockAllKeysWithSamePassword()
            throws IOException, PGPException {

        OpenPGPKey key = TestKeys.getCryptieKey();
        SecretKeyRingProtector protector =
                SecretKeyRingProtector.unlockEachKeyWith(TestKeys.CRYPTIE_PASSPHRASE, key);
        for (OpenPGPKey.OpenPGPSecretKey secretKey : key.getSecretKeys().values()) {
            assertNotNull(secretKey.unlock(protector));
        }

        OpenPGPKey unrelatedKey = PGPainless.getInstance().generateKey()
                .simpleEcKeyRing("unrelated",
                "SecurePassword");
        for (OpenPGPKey.OpenPGPSecretKey k : unrelatedKey.getSecretKeys().values()) {
            assertThrows(PGPException.class, () -> k.unlock(protector));
        }
    }

    @Test
    public void testUnprotectedKeys() throws PGPException {
        Random random = new Random();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        for (int i = 0; i < 10; i++) {
            KeyIdentifier keyIdentifier = new KeyIdentifier(random.nextLong());
            assertNull(protector.getDecryptor(keyIdentifier));
        }
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testUnlockSingleKeyWithPassphrase()
            throws IOException, PGPException {
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();
        Iterator<OpenPGPKey.OpenPGPSecretKey> iterator = secretKeys.getSecretKeys().values().iterator();
        OpenPGPKey.OpenPGPSecretKey key = iterator.next();
        OpenPGPKey.OpenPGPSecretKey subKey = iterator.next();

        SecretKeyRingProtector protector =
                SecretKeyRingProtector.unlockSingleKeyWith(TestKeys.CRYPTIE_PASSPHRASE, key);
        assertNotNull(protector.getDecryptor(key.getKeyIdentifier()));
        assertNotNull(protector.getEncryptor(key.getPublicKey()));
        assertNull(protector.getEncryptor(subKey.getPublicKey()));
        assertNull(protector.getDecryptor(subKey.getKeyIdentifier()));
    }

    @Test
    public void testFromPassphraseMap() {
        Map<KeyIdentifier, Passphrase> passphraseMap = new ConcurrentHashMap<>();
        KeyIdentifier k1 = new KeyIdentifier(1L);
        KeyIdentifier k5 = new KeyIdentifier(5L);
        passphraseMap.put(k1, Passphrase.emptyPassphrase());
        CachingSecretKeyRingProtector protector =
                (CachingSecretKeyRingProtector) SecretKeyRingProtector.fromPassphraseMap(passphraseMap);

        assertNotNull(protector.getPassphraseFor(k1));
        assertNull(protector.getPassphraseFor(k5));

        protector.addPassphrase(k5, Passphrase.fromPassword("pa55w0rd"));
        protector.forgetPassphrase(k1);

        assertNull(protector.getPassphraseFor(k1));
        assertNotNull(protector.getPassphraseFor(k5));
    }

    @Test
    public void testMissingPassphraseCallback() {
        Map<KeyIdentifier, Passphrase> passphraseMap = new ConcurrentHashMap<>();
        passphraseMap.put(new KeyIdentifier(1L), Passphrase.emptyPassphrase());
        CachingSecretKeyRingProtector protector = new CachingSecretKeyRingProtector(passphraseMap,
                KeyRingProtectionSettings.secureDefaultSettings(), new SecretKeyPassphraseProvider() {
            @Override
            public Passphrase getPassphraseFor(@NotNull KeyIdentifier keyIdentifier) {
                return Passphrase.fromPassword("missingP455w0rd");
            }

            @Override
            public boolean hasPassphrase(@NotNull KeyIdentifier keyIdentifier) {
                return true;
            }
        });

        assertEquals(Passphrase.emptyPassphrase(), protector.getPassphraseFor(new KeyIdentifier(1L)));
        assertEquals(Passphrase.fromPassword("missingP455w0rd"), protector.getPassphraseFor(new KeyIdentifier(3L)));
    }
}
