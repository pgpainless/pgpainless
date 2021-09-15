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
package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Random;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

public class CachingSecretKeyRingProtectorTest {

    // Dummy passphrase callback that returns the doubled key-id as passphrase
    private final SecretKeyPassphraseProvider dummyCallback = new SecretKeyPassphraseProvider() {
        @Nullable
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
    public void noCallbackReturnsNullForUnknownKeyId() throws PGPException {
        assertNull(protector.getDecryptor(123L));
        assertNull(protector.getEncryptor(123L));
    }

    @Test
    public void testAddPassphrase() throws PGPException {
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
    public void testAddPassphraseForKeyRing() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing keys = PGPainless.generateKeyRing()
                .modernKeyRing("test@test.test", "Passphrase123");
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
            assertEquals(doubled, Long.valueOf(new String(passphrase.getChars())));
        }
    }

}
