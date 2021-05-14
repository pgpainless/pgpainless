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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.util.Passphrase;

public class UnlockSecretKeyTest {

    @Test
    public void testUnlockSecretKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeyRing = PGPainless.generateKeyRing()
                .simpleEcKeyRing("alice@wonderland.lit", "heureka!");
        PGPSecretKey secretKey = secretKeyRing.getSecretKey();

        SecretKeyRingProtector correctPassphrase = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword("heureka!"), secretKeyRing);
        SecretKeyRingProtector incorrectPassphrase = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword("bazinga!"), secretKeyRing);
        SecretKeyRingProtector emptyPassphrase = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.emptyPassphrase(), secretKeyRing);
        Passphrase cleared = Passphrase.fromPassword("cleared");
        cleared.clear();
        SecretKeyRingProtector invalidPassphrase = SecretKeyRingProtector.unlockAllKeysWith(cleared, secretKeyRing);
        // Correct passphrase works
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, correctPassphrase);
        assertNotNull(privateKey);

        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey, incorrectPassphrase));
        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey, emptyPassphrase));
        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey, invalidPassphrase));
    }
}
