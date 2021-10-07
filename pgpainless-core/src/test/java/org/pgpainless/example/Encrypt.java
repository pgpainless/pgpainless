// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.Passphrase;

public class Encrypt {

    /**
     * In this example, Alice is sending a signed and encrypted message to Bob.
     * She signs the message using her key and then encrypts the message to both bobs certificate and her own.
     *
     * Bob subsequently decrypts the message using his key and verifies that the message was signed by Alice using
     * her certificate.
     */
    @Test
    public void encryptAndSignMessage() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        // Prepare keys
        PGPSecretKeyRing keyAlice = PGPainless.generateKeyRing()
                .modernKeyRing("alice@pgpainless.org", null);
        PGPPublicKeyRing certificateAlice = KeyRingUtils.publicKeyRingFrom(keyAlice);
        SecretKeyRingProtector protectorAlice = SecretKeyRingProtector.unprotectedKeys();

        PGPSecretKeyRing keyBob = PGPainless.generateKeyRing()
                .modernKeyRing("bob@pgpainless.org", null);
        PGPPublicKeyRing certificateBob = KeyRingUtils.publicKeyRingFrom(keyBob);
        SecretKeyRingProtector protectorBob = SecretKeyRingProtector.unprotectedKeys();

        // plaintext message to encrypt
        String message = "Hello, World!\n";
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        // Encrypt and sign
        EncryptionStream encryptor = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertext)
                .withOptions(ProducerOptions.signAndEncrypt(
                        // we want to encrypt communication (affects key selection based on key flags)
                        EncryptionOptions.encryptCommunications()
                                .addRecipient(certificateBob)
                                .addRecipient(certificateAlice),
                        new SigningOptions()
                                .addInlineSignature(protectorAlice, keyAlice, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                        ).setAsciiArmor(true)
                );

        // Pipe data trough and CLOSE the stream (important)
        Streams.pipeAll(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), encryptor);
        encryptor.close();
        String encryptedMessage = ciphertext.toString();

        // Decrypt and verify signatures
        DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(keyBob, protectorBob)
                        .addVerificationCert(certificateAlice)
                );

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, plaintext);
        decryptor.close();

        // Check the metadata to see how the message was encrypted/signed
        OpenPgpMetadata metadata = decryptor.getResult();
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.containsVerifiedSignatureFrom(certificateAlice));
        assertEquals(message, plaintext.toString());
    }

    /**
     * This example demonstrates how to encrypt and decrypt a message using a passphrase.
     * This method can be combined with public key based encryption and signing.
     *
     * @throws PGPException
     * @throws IOException
     */
    @Test
    public void encryptUsingPassphrase() throws PGPException, IOException {
        String message = "Hello, World!";
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        // Encrypt
        EncryptionStream encryptor = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertext)
                .withOptions(ProducerOptions
                        .encrypt(EncryptionOptions.encryptCommunications()
                                .addPassphrase(Passphrase.fromPassword("p4ssphr4s3"))
                        ).setAsciiArmor(true)
                );

        Streams.pipeAll(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), encryptor);
        encryptor.close();

        String asciiCiphertext = ciphertext.toString();

        // Decrypt
        DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(asciiCiphertext.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions().addDecryptionPassphrase(Passphrase.fromPassword("p4ssphr4s3")));

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        Streams.pipeAll(decryptor, plaintext);

        decryptor.close();

        assertEquals(message, plaintext.toString());
    }
}
