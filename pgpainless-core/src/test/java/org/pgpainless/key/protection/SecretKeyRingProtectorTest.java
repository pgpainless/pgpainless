// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class SecretKeyRingProtectorTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testUnlockAllKeysWithSamePassword()
            throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {

        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        SecretKeyRingProtector protector =
                SecretKeyRingProtector.unlockEachKeyWith(TestKeys.CRYPTIE_PASSPHRASE, secretKeys);
        for (PGPSecretKey secretKey : secretKeys) {
            PBESecretKeyDecryptor decryptor = protector.getDecryptor(secretKey.getKeyID());
            assertNotNull(decryptor);
            secretKey.extractPrivateKey(decryptor);
        }
        PGPSecretKeyRing unrelatedKeys = PGPainless.generateKeyRing().simpleEcKeyRing("unrelated",
                "SecurePassword");
        for (PGPSecretKey unrelatedKey : unrelatedKeys) {
            PBESecretKeyDecryptor decryptor = protector.getDecryptor(unrelatedKey.getKeyID());
            assertNull(decryptor);
            assertThrows(PGPException.class,
                    () -> unrelatedKey.extractPrivateKey(protector.getDecryptor(unrelatedKey.getKeyID())));
        }
    }

    @Test
    public void testUnprotectedKeys() throws PGPException {
        Random random = new Random();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        for (int i = 0; i < 10; i++) {
            Long keyId = random.nextLong();
            assertNull(protector.getEncryptor(keyId));
            assertNull(protector.getDecryptor(keyId));
        }
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testUnlockSingleKeyWithPassphrase()
            throws IOException, PGPException {

        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        Iterator<PGPSecretKey> iterator = secretKeys.iterator();
        PGPSecretKey secretKey = iterator.next();
        PGPSecretKey subKey = iterator.next();

        SecretKeyRingProtector protector =
                SecretKeyRingProtector.unlockSingleKeyWith(TestKeys.CRYPTIE_PASSPHRASE, secretKey);
        assertNotNull(protector.getDecryptor(secretKey.getKeyID()));
        assertNotNull(protector.getEncryptor(secretKey.getKeyID()));
        assertNull(protector.getEncryptor(subKey.getKeyID()));
        assertNull(protector.getDecryptor(subKey.getKeyID()));
    }

    @Test
    public void testFromPassphraseMap() {
        Map<Long, Passphrase> passphraseMap = new ConcurrentHashMap<>();
        passphraseMap.put(1L, Passphrase.emptyPassphrase());
        CachingSecretKeyRingProtector protector =
                (CachingSecretKeyRingProtector) SecretKeyRingProtector.fromPassphraseMap(passphraseMap);

        assertNotNull(protector.getPassphraseFor(1L));
        assertNull(protector.getPassphraseFor(5L));

        protector.addPassphrase(5L, Passphrase.fromPassword("pa55w0rd"));
        protector.forgetPassphrase(1L);

        assertNull(protector.getPassphraseFor(1L));
        assertNotNull(protector.getPassphraseFor(5L));
    }

    @Test
    public void testMissingPassphraseCallback() {
        Map<Long, Passphrase> passphraseMap = new ConcurrentHashMap<>();
        passphraseMap.put(1L, Passphrase.emptyPassphrase());
        CachingSecretKeyRingProtector protector = new CachingSecretKeyRingProtector(passphraseMap,
                KeyRingProtectionSettings.secureDefaultSettings(), new SecretKeyPassphraseProvider() {
            @Nullable
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                return Passphrase.fromPassword("missingP455w0rd");
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return true;
            }
        });

        assertEquals(Passphrase.emptyPassphrase(), protector.getPassphraseFor(1L));
        assertEquals(Passphrase.fromPassword("missingP455w0rd"), protector.getPassphraseFor(3L));
    }
}
