// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.symmetric_encryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MissingKeyPassphraseStrategy;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.exception.MissingDecryptionMethodException;
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

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void encryptWithKeyAndPassphrase_DecryptWithKey() throws IOException, PGPException {
        byte[] plaintext = "This is a secret message".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream(plaintext);
        PGPPublicKeyRing encryptionKey = TestKeys.getCryptiePublicKeyRing();
        Passphrase encryptionPassphrase = Passphrase.fromPassword("greenBeans");

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptor = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertextOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.encryptCommunications()
                                .addMessagePassphrase(encryptionPassphrase)
                                .addRecipient(encryptionKey)
                ));

        Streams.pipeAll(plaintextIn, encryptor);
        encryptor.close();

        byte[] ciphertext = ciphertextOut.toByteArray();

        // Test symmetric decryption
        DecryptionStream decryptor = PGPainless.getInstance().processMessage()
                .onInputStream(new ByteArrayInputStream(ciphertext))
                .withOptions(ConsumerOptions.get()
                        .addMessagePassphrase(encryptionPassphrase));

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decrypted);
        decryptor.close();

        assertArrayEquals(plaintext, decrypted.toByteArray());

        // Test public key decryption
        PGPSecretKeyRingCollection decryptionKeys = TestKeys.getCryptieSecretKeyRingCollection();
        SecretKeyRingProtector protector = new PasswordBasedSecretKeyRingProtector(
                KeyRingProtectionSettings.secureDefaultSettings(),
                new SolitaryPassphraseProvider(Passphrase.fromPassword(TestKeys.CRYPTIE_PASSWORD)));
        decryptor = PGPainless.getInstance().processMessage()
                .onInputStream(new ByteArrayInputStream(ciphertext))
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKeys(decryptionKeys, protector));

        decrypted = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decrypted);
        decryptor.close();

        assertArrayEquals(plaintext, decrypted.toByteArray());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testMismatchPassphraseFails() throws IOException, PGPException {
        byte[] bytes = new byte[5000];
        new Random().nextBytes(bytes);

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptor = PGPainless.getInstance().generateMessage().onOutputStream(ciphertextOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.encryptCommunications()
                                .addMessagePassphrase(Passphrase.fromPassword("mellon"))));

        Streams.pipeAll(new ByteArrayInputStream(bytes), encryptor);
        encryptor.close();

        assertThrows(MissingDecryptionMethodException.class, () -> PGPainless.getInstance().processMessage()
                .onInputStream(new ByteArrayInputStream(ciphertextOut.toByteArray()))
                .withOptions(ConsumerOptions.get()
                        .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.THROW_EXCEPTION)
                        .addMessagePassphrase(Passphrase.fromPassword("meldir"))));
    }
}
