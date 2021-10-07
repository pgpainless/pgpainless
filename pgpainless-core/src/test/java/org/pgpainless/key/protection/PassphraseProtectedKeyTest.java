// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

public class PassphraseProtectedKeyTest {

    /**
     * Protector that holds only the password of cryptie.
     */
    private final PasswordBasedSecretKeyRingProtector protector = new PasswordBasedSecretKeyRingProtector(
            KeyRingProtectionSettings.secureDefaultSettings(),
            new SecretKeyPassphraseProvider() {
                @Nullable
                @Override
                public Passphrase getPassphraseFor(Long keyId) {
                    if (keyId.equals(TestKeys.CRYPTIE_KEY_ID)) {
                        return new Passphrase(TestKeys.CRYPTIE_PASSWORD.toCharArray());
                    } else {
                        return null;
                    }
                }

                @Override
                public boolean hasPassphrase(Long keyId) {
                    return keyId.equals(TestKeys.CRYPTIE_KEY_ID);
                }
            });

    @Test
    public void testReturnsNonNullDecryptorEncryptorForPassword() throws PGPException {
        assertNotNull(protector.getEncryptor(TestKeys.CRYPTIE_KEY_ID));
        assertNotNull(protector.getDecryptor(TestKeys.CRYPTIE_KEY_ID));
    }

    @Test
    public void testReturnsNullDecryptorEncryptorForNoPassword() throws PGPException {
        assertNull(protector.getEncryptor(TestKeys.JULIET_KEY_ID));
        assertNull(protector.getDecryptor(TestKeys.JULIET_KEY_ID));
    }

    @Test
    public void testReturnsNonNullDecryptorForSubkeys() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("alice", "passphrase");
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("passphrase"));
        for (Iterator<PGPPublicKey> it = secretKeys.getPublicKeys(); it.hasNext(); ) {
            PGPPublicKey subkey = it.next();
            assertNotNull(protector.getEncryptor(subkey.getKeyID()));
            assertNotNull(protector.getDecryptor(subkey.getKeyID()));
        }
    }
}
