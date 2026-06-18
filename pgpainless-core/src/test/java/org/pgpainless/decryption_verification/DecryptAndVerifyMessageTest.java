// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import kotlin.Pair;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class DecryptAndVerifyMessageTest {

    // Don't use StandardCharsets.UTF8 because of Android API level.
    @SuppressWarnings("CharsetObjectCanBeUsed")
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private PGPSecretKeyRing juliet;
    private PGPSecretKeyRing romeo;

    @BeforeEach
    public void loadKeys() throws IOException, PGPException {
        juliet = TestKeys.getJulietSecretKeyRing();
        romeo = TestKeys.getRomeoSecretKeyRing();
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void decryptMessageAndVerifySignatureTest() throws Exception {
        String encryptedMessage = TestKeys.MSG_SIGN_CRYPT_JULIET_JULIET;

        ConsumerOptions options = ConsumerOptions.get()
                .addDecryptionKey(juliet)
                .addVerificationCert(KeyRingUtils.publicKeyRingFrom(juliet));

        DecryptionStream decryptor = PGPainless.getInstance().processMessage()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes()))
                .withOptions(options);

        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();
        Streams.pipeAll(decryptor, toPlain);
        decryptor.close();
        toPlain.close();
        MessageMetadata metadata = decryptor.getMetadata();

        byte[] expected = TestKeys.TEST_MESSAGE_01_PLAIN.getBytes(UTF8);
        byte[] actual = toPlain.toByteArray();

        assertArrayEquals(expected, actual);

        assertTrue(metadata.isEncrypted());
        assertFalse(metadata.isUsingCleartextSignatureFramework());
        assertTrue(metadata.isVerifiedSigned());
        assertEquals(CompressionAlgorithm.ZLIB, metadata.getCompressionAlgorithm());
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getEncryptionAlgorithm());
        assertEquals(1, metadata.getVerifiedSignatures().size());
        assertEquals(1, metadata.getVerifiedSignatures().size());
        assertTrue(metadata.isVerifiedSignedBy(TestKeys.JULIET_FINGERPRINT));
        assertEquals(new SubkeyIdentifier(TestKeys.JULIET_FINGERPRINT), metadata.getDecryptionKey());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void decryptMessageAndReadBeyondEndTest() throws Exception {
        final String encryptedMessage = TestKeys.MSG_SIGN_CRYPT_JULIET_JULIET;

        final ConsumerOptions options = ConsumerOptions.get()
                .addDecryptionKey(juliet)
                .addVerificationCert(KeyRingUtils.publicKeyRingFrom(juliet));

        try (DecryptionStream decryptor = PGPainless.getInstance().processMessage()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes()))
                .withOptions(options);
             ByteArrayOutputStream toPlain = new ByteArrayOutputStream()) {
            Streams.pipeAll(decryptor, toPlain);
            assertEquals(-1, decryptor.read());
        }
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void decryptMessageAndVerifySignatureByteByByteTest() throws Exception {
        String encryptedMessage = TestKeys.MSG_SIGN_CRYPT_JULIET_JULIET;

        ConsumerOptions options = ConsumerOptions.get()
                .addDecryptionKey(juliet)
                .addVerificationCert(KeyRingUtils.publicKeyRingFrom(juliet));

        DecryptionStream decryptor = PGPainless.getInstance().processMessage()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes()))
                .withOptions(options);

        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();
        int r;
        while ((r = decryptor.read()) != -1) {
            toPlain.write(r);
        }

        decryptor.close();
        toPlain.close();
        MessageMetadata metadata = decryptor.getMetadata();

        byte[] expected = TestKeys.TEST_MESSAGE_01_PLAIN.getBytes(UTF8);
        byte[] actual = toPlain.toByteArray();

        assertArrayEquals(expected, actual);

        assertTrue(metadata.isEncrypted());
        assertFalse(metadata.isUsingCleartextSignatureFramework());
        assertTrue(metadata.isVerifiedSigned());
        assertEquals(CompressionAlgorithm.ZLIB, metadata.getCompressionAlgorithm());
        assertEquals(SymmetricKeyAlgorithm.AES_256, metadata.getEncryptionAlgorithm());
        assertEquals(1, metadata.getVerifiedSignatures().size());
        assertEquals(1, metadata.getVerifiedSignatures().size());
        assertTrue(metadata.isVerifiedSignedBy(TestKeys.JULIET_FINGERPRINT));
        assertEquals(new SubkeyIdentifier(TestKeys.JULIET_FINGERPRINT), metadata.getDecryptionKey());
    }

    @Test
    public void testDecryptMessageWithUnacceptableSymmetricAlgorithm() {
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "jA0EAQMCZv8glrLeXPhg0jgBpMN+E8dCuEDxJnSi8/e+HOKcdYQbgQh/MG4Kn7NK\n" +
                "wRM5wNOFKn8jbsoC+JalzjwzMJSV+ZM1aQ==\n" +
                "=9aCQ\n" +
                "-----END PGP MESSAGE-----";
        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext.getBytes());
        assertThrows(MissingDecryptionMethodException.class,
                () -> PGPainless.getInstance().processMessage()
                        .onInputStream(ciphertextIn)
                        .withOptions(ConsumerOptions.get()
                                .addMessagePassphrase(Passphrase.fromPassword("sw0rdf1sh"))));
    }

    @Test
    public void testVerifyAndOpenHelperMethod() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.get(api).addRecipient(key),
                        SigningOptions.get(api).addSignature(SecretKeyRingProtector.unprotectedKeys(), key)));
        eOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        eOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream dIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .addVerificationCert(key)
                        .addDecryptionKey(key));

        DecryptionStream verified = PGPainless.verifyAndOpen(dIn);
        assertTrue(verified.getMetadata().isVerifiedSignedBy(key));
        assertArrayEquals("Hello, World!\n".getBytes(StandardCharsets.UTF_8), verified.readAllBytes());
    }
}
