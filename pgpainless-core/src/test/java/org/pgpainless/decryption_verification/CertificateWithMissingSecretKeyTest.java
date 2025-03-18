// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;

public class CertificateWithMissingSecretKeyTest {

    private static final String MISSING_SIGNING_SECKEY = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: E97B 15E6 52FA 8BAE 2311  DDCB A5BD 9DC4 4415 C987\n" +
            "Comment: Missing Signing Subkey <missing@signing.subkey>\n" +
            "\n" +
            "lFgEYjCuERYJKwYBBAHaRw8BAQdAaqeTdbyb/D+UXd2aXsP58+k+tvt22DnL6bC0\n" +
            "7p2tJacAAP0fEmwUY7rSPugQakzsA8nV4Nv3PYlKa6meqEePT+8s8BFitC9NaXNz\n" +
            "aW5nIFNpZ25pbmcgU3Via2V5IDxtaXNzaW5nQHNpZ25pbmcuc3Via2V5PoiPBBMW\n" +
            "CgBBBQJiMK4RCRClvZ3ERBXJhxYhBOl7FeZS+ouuIxHdy6W9ncREFcmHAp4BApsB\n" +
            "BRYCAwEABAsJCAcFFQoJCAsCmQEAAN0HAPkB7IphgTM94s/VpyV5+hvYbxesnji5\n" +
            "RNzqs3nRhS8DBgEA/+gCpAkgznB3T/uNtWIoTf7Kuib5mIJ+SW0l+htuEgacXQRi\n" +
            "MK4REgorBgEEAZdVAQUBAQdAlaQH44c7PdKkjaVVXvg86i+thKV121C/nH75Krhh\n" +
            "QxYDAQgHAAD/aWJt9M85Al+57lPqS5ppzrIoCoTZ6JCwuJUSNEAg4BgQ6Ih1BBgW\n" +
            "CgAdBQJiMK4RAp4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQpb2dxEQVyYdzuAD9\n" +
            "GEkU7NfugHw8alQT7IJbUobVyZzeXQyzPqSKUw/Vp54BAJXZj8NzQrrM4Q5C3+Mf\n" +
            "uznN+ryRovDXhf8T5PUXHloDuDMEYjCuERYJKwYBBAHaRw8BAQdAVeBpPurrwAU3\n" +
            "ns+1C2c6wJ8iTZ1eWEP2qgBAlokx5N+I1QQYFgoAfQUCYjCuEQKeAQKbAgUWAgMB\n" +
            "AAQLCQgHBRUKCQgLXyAEGRYKAAYFAmIwrhEACgkQld4KwYO6xR4YEwEA942iduoW\n" +
            "1ANEmwCwnYwMAa3HlXsMs5bdIUGnxuo7MBEA/1YYeAu45O2Z8kTdrDZM/1emoxt1\n" +
            "j6EzybnaJ+2XGX4AAAoJEKW9ncREFcmHLXsBAITCIwGtaCvZdWCQlJeYak1NTuBp\n" +
            "bmOEFga0sLmRI/zYAP97U2oc8dqV55S1b4yNkfENK2MD6Ow0nv8CL6+S0UaCBw==\n" +
            "=eTh7\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final long signingSubkeyId = -7647663290973502178L;
    private static PGPSecretKeyRing missingSigningSecKey;

    private static KeyIdentifier encryptionSubkeyId;
    private static PGPSecretKeyRing missingDecryptionSecKey;

    private static final SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();


    @BeforeAll
    public static void prepare() throws IOException {
        // missing signing sec key we read from bytes
        missingSigningSecKey = PGPainless.readKeyRing().secretKeyRing(MISSING_SIGNING_SECKEY);

        // missing encryption sec key we generate on the fly
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Missing Decryption Key <missing@decryption.key>")
                .getPGPSecretKeyRing();
        encryptionSubkeyId = PGPainless.inspectKeyRing(secretKeys)
                .getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getKeyIdentifier();
        // remove the encryption/decryption secret key
        missingDecryptionSecKey = KeyRingUtils.stripSecretKey(secretKeys, encryptionSubkeyId.getKeyId());
    }

    @Test
    public void assureMissingSigningSecKeyOnlyContainSigningPubKey() {
        assertNotNull(missingSigningSecKey.getPublicKey(signingSubkeyId));
        assertNull(missingSigningSecKey.getSecretKey(signingSubkeyId));

        KeyRingInfo info = PGPainless.inspectKeyRing(missingSigningSecKey);
        assertFalse(info.getSigningSubkeys().isEmpty()); // This method only tests for pub keys.
    }

    @Test
    public void assureMissingDecryptionSecKeyOnlyContainsEncryptionPubKey() {
        assertNotNull(missingDecryptionSecKey.getPublicKey(encryptionSubkeyId));
        assertNull(missingDecryptionSecKey.getSecretKey(encryptionSubkeyId));

        KeyRingInfo info = PGPainless.inspectKeyRing(missingDecryptionSecKey);
        assertFalse(info.getEncryptionSubkeys(EncryptionPurpose.ANY).isEmpty()); // pub key is still there
    }

    @Test
    public void testSignWithMissingSigningSecKey() {
        SigningOptions signingOptions = SigningOptions.get();

        assertThrows(KeyException.MissingSecretKeyException.class, () ->
                signingOptions.addInlineSignature(protector, missingSigningSecKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
        assertThrows(KeyException.MissingSecretKeyException.class, () ->
                signingOptions.addDetachedSignature(protector, missingSigningSecKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }

    @Test
    public void testEncryptDecryptWithMissingDecryptionKey() throws PGPException, IOException {
        ByteArrayInputStream in = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        PGPPublicKeyRing certificate = PGPainless.extractCertificate(missingDecryptionSecKey);
        ProducerOptions producerOptions = ProducerOptions.encrypt(
                EncryptionOptions.encryptCommunications()
                        .addRecipient(certificate));  // we can still encrypt, since the pub key is still there

        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(producerOptions);

        Streams.pipeAll(in, encryptionStream);
        encryptionStream.close();

        assertTrue(encryptionStream.getResult().isEncryptedFor(certificate));

        // Test decryption
        ByteArrayInputStream cipherIn = new ByteArrayInputStream(out.toByteArray());

        ConsumerOptions consumerOptions = ConsumerOptions.get()
                .addDecryptionKey(missingDecryptionSecKey);

        assertThrows(MissingDecryptionMethodException.class, () ->
                PGPainless.decryptAndOrVerify()
                        .onInputStream(cipherIn)
                        .withOptions(consumerOptions)); // <- cannot find decryption key
    }
}
