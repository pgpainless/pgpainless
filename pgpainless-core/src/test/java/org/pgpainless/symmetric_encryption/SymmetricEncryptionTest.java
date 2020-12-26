/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.symmetric_encryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider;
import org.pgpainless.util.Passphrase;

/**
 * Test parallel symmetric and public key encryption/decryption.
 */
public class SymmetricEncryptionTest {

    @Test
    public void test() throws IOException, PGPException {
        byte[] plaintext = "This is a secret message".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream(plaintext);
        PGPPublicKeyRing encryptionKey = TestKeys.getCryptiePublicKeyRing();
        Passphrase encryptionPassphrase = Passphrase.fromPassword("greenBeans");

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptor = PGPainless.encryptAndOrSign().onOutputStream(ciphertextOut)
                .forPassphrases(encryptionPassphrase)
                .and()
                .toRecipients(encryptionKey)
                .usingSecureAlgorithms()
                .doNotSign()
                .noArmor();

        Streams.pipeAll(plaintextIn, encryptor);
        encryptor.close();

        byte[] ciphertext = ciphertextOut.toByteArray();

        // Test symmetric decryption
        DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ciphertext))
                .decryptWith(encryptionPassphrase)
                .doNotVerify()
                .build();

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decrypted);
        decryptor.close();

        assertArrayEquals(plaintext, decrypted.toByteArray());

        // Test public key decryption
        PGPSecretKeyRingCollection decryptionKeys = TestKeys.getCryptieSecretKeyRingCollection();
        SecretKeyRingProtector protector = new PasswordBasedSecretKeyRingProtector(
                KeyRingProtectionSettings.secureDefaultSettings(),
                new SolitaryPassphraseProvider(Passphrase.fromPassword(TestKeys.CRYPTIE_PASSWORD)));
        decryptor = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ciphertext))
                .decryptWith(protector, decryptionKeys)
                .doNotVerify()
                .build();

        decrypted = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decrypted);
        decryptor.close();

        assertArrayEquals(plaintext, decrypted.toByteArray());
    }
}
