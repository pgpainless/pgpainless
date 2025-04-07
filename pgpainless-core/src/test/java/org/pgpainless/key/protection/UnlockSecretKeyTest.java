// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
    public void testUnlockSecretKey() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        PGPSecretKeyRing secretKeyRing = api.generateKey()
                .simpleEcKeyRing("alice@wonderland.lit", "heureka!")
                .getPGPSecretKeyRing();
        PGPSecretKey secretKey = secretKeyRing.getSecretKey();

        SecretKeyRingProtector correctPassphrase = SecretKeyRingProtector
                .unlockAnyKeyWith(Passphrase.fromPassword("heureka!"));
        SecretKeyRingProtector incorrectPassphrase = SecretKeyRingProtector
                .unlockAnyKeyWith(Passphrase.fromPassword("bazinga!"));
        SecretKeyRingProtector emptyPassphrase = SecretKeyRingProtector
                .unlockAnyKeyWith(Passphrase.emptyPassphrase());
        Passphrase cleared = Passphrase.fromPassword("cleared");
        cleared.clear();
        SecretKeyRingProtector invalidPassphrase = SecretKeyRingProtector
                .unlockAnyKeyWith(cleared);

        // Correct passphrase works
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, correctPassphrase);
        assertNotNull(privateKey);

        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey, incorrectPassphrase));
        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey, emptyPassphrase));
        assertThrows(IllegalStateException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey, invalidPassphrase));
    }
}
