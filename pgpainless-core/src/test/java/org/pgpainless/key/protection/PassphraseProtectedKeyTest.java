// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.jetbrains.annotations.NotNull;
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
                public Passphrase getPassphraseFor(@NotNull KeyIdentifier keyIdentifier) {
                    if (keyIdentifier.getKeyId() == TestKeys.CRYPTIE_KEY_ID) {
                        return new Passphrase(TestKeys.CRYPTIE_PASSWORD.toCharArray());
                    } else {
                        return null;
                    }
                }

                @Override
                public boolean hasPassphrase(@NotNull KeyIdentifier keyIdentifier) {
                    return keyIdentifier.getKeyId() == TestKeys.CRYPTIE_KEY_ID;
                }
            });

    @Test
    public void testReturnsNonNullDecryptorEncryptorForPassword() throws IOException {
        assertNotNull(protector.getEncryptor(TestKeys.getCryptiePublicKeyRing().getPublicKey(TestKeys.CRYPTIE_KEY_ID)));
        assertNotNull(protector.getDecryptor(TestKeys.CRYPTIE_KEY_ID));
    }

    @Test
    public void testReturnsNullDecryptorEncryptorForNoPassword() throws IOException {
        assertNull(protector.getEncryptor(TestKeys.getJulietPublicKeyRing().getPublicKey(TestKeys.JULIET_KEY_ID)));
        assertNull(protector.getDecryptor(TestKeys.JULIET_KEY_ID));
    }

    @Test
    public void testReturnsNonNullDecryptorForSubkeys() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.generateKey()
                .modernKeyRing("alice <alice@example.org>", "passphrase");
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector.forKey(key, Passphrase.fromPassword("passphrase"));
        for (OpenPGPCertificate.OpenPGPComponentKey subkey : key.getPublicKeys().values()) {
            assertNotNull(protector.getEncryptor(subkey));
            assertNotNull(protector.getDecryptor(subkey.getKeyIdentifier()));
            assertNotNull(protector.getDecryptor(subkey.getKeyIdentifier().getKeyId()));
        }
    }
}
