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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyReader;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class Encrypt {

    private static final String ALICE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 12E3 4F04 C66D 2B70 D16C  960D ACF2 16F0 F93D DD20\n" +
            "Comment: alice@pgpainless.org\n" +
            "\n" +
            "lFgEYksu1hYJKwYBBAHaRw8BAQdAIhUpRrs6zFTBI1pK40jCkzY/DQ/t4fUgNtlS\n" +
            "mXOt1cIAAP4wM0LQD/Wj9w6/QujM/erj/TodDZzmp2ZwblrvDQri0RJ/tBRhbGlj\n" +
            "ZUBwZ3BhaW5sZXNzLm9yZ4iPBBMWCgBBBQJiSy7WCRCs8hbw+T3dIBYhBBLjTwTG\n" +
            "bStw0WyWDazyFvD5Pd0gAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAAOOTAQDf\n" +
            "UsRQSAs0d/Nm4YIrq+gU7gOdTJuf33f/u/u1nGM1fAD/RY7I3gQoZ0lWbvXVkRAL\n" +
            "Cu9cUJdvL7kpW1oYtYg21QucXQRiSy7WEgorBgEEAZdVAQUBAQdA60F84k6MY/Uy\n" +
            "BCZe4/WP8JDw/Efu5/Gyk8hcd3HzHFsDAQgHAAD/aC8DOOkK0XNVz2hkSVczmNoJ\n" +
            "Umog0PfQLRujpOTqonAQKIh1BBgWCgAdBQJiSy7WAp4BApsMBRYCAwEABAsJCAcF\n" +
            "FQoJCAsACgkQrPIW8Pk93SCd6AD/Y3LF2RvgbEaOBtAvH6w0ZBPorB3rk6dx+Ae0\n" +
            "GvW4E8wA+QHmgNo0pdkDxTl0BN1KC7BV1iRFqe9Vo7fW2LLfhlEEnFgEYksu1hYJ\n" +
            "KwYBBAHaRw8BAQdAPtqap21/zmVzxOHk++891/EZSNikwWkq9t0pmYjhtJ8AAP9N\n" +
            "m/G6nbiEB8mu/TkNnb7vdhSmLddL9kdKh0LzWD95LBF0iNUEGBYKAH0FAmJLLtYC\n" +
            "ngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJiSy7WAAoJEOEz2Vo79Yyl\n" +
            "zN0A/iZAVklSJsfQslshR6/zMBufwCK1S05jg/5Ydaksv3QcAQC4gsxdFFne+H4M\n" +
            "mos4atad6hMhlqr0/Zyc71ZdO5I/CAAKCRCs8hbw+T3dIGhqAQCIdVtCus336cDe\n" +
            "Nug+E9v1PEM3F/dt6GAqSG8LJqdAGgEA8cUXdUBooOo/QBkDnpteke8Z3IhIGyGe\n" +
            "dc8OwJyVFwc=\n" +
            "=ARAi\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    private static final String ALICE_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 12E3 4F04 C66D 2B70 D16C  960D ACF2 16F0 F93D DD20\n" +
            "Comment: alice@pgpainless.org\n" +
            "\n" +
            "mDMEYksu1hYJKwYBBAHaRw8BAQdAIhUpRrs6zFTBI1pK40jCkzY/DQ/t4fUgNtlS\n" +
            "mXOt1cK0FGFsaWNlQHBncGFpbmxlc3Mub3JniI8EExYKAEEFAmJLLtYJEKzyFvD5\n" +
            "Pd0gFiEEEuNPBMZtK3DRbJYNrPIW8Pk93SACngECmwEFFgIDAQAECwkIBwUVCgkI\n" +
            "CwKZAQAA45MBAN9SxFBICzR382bhgiur6BTuA51Mm5/fd/+7+7WcYzV8AP9Fjsje\n" +
            "BChnSVZu9dWREAsK71xQl28vuSlbWhi1iDbVC7g4BGJLLtYSCisGAQQBl1UBBQEB\n" +
            "B0DrQXziToxj9TIEJl7j9Y/wkPD8R+7n8bKTyFx3cfMcWwMBCAeIdQQYFgoAHQUC\n" +
            "Yksu1gKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEKzyFvD5Pd0gnegA/2Nyxdkb\n" +
            "4GxGjgbQLx+sNGQT6Kwd65OncfgHtBr1uBPMAPkB5oDaNKXZA8U5dATdSguwVdYk\n" +
            "RanvVaO31tiy34ZRBLgzBGJLLtYWCSsGAQQB2kcPAQEHQD7amqdtf85lc8Th5Pvv\n" +
            "PdfxGUjYpMFpKvbdKZmI4bSfiNUEGBYKAH0FAmJLLtYCngECmwIFFgIDAQAECwkI\n" +
            "BwUVCgkIC18gBBkWCgAGBQJiSy7WAAoJEOEz2Vo79YylzN0A/iZAVklSJsfQslsh\n" +
            "R6/zMBufwCK1S05jg/5Ydaksv3QcAQC4gsxdFFne+H4Mmos4atad6hMhlqr0/Zyc\n" +
            "71ZdO5I/CAAKCRCs8hbw+T3dIGhqAQCIdVtCus336cDeNug+E9v1PEM3F/dt6GAq\n" +
            "SG8LJqdAGgEA8cUXdUBooOo/QBkDnpteke8Z3IhIGyGedc8OwJyVFwc=\n" +
            "=GUhm\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String BOB_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: A0D2 F316 0F6B 2CE5 7A50  FF32 261E 5081 9736 C493\n" +
            "Comment: bob@pgpainless.org\n" +
            "\n" +
            "lFgEYksu1hYJKwYBBAHaRw8BAQdAXTBT1OKN1GAvGC+fzuy/k34BK+d5Saa87Glb\n" +
            "iQgIxg8AAPwMI5DGqADFfl6H3Nxj3NxEZLasiFDpwEszluLVRy0jihGbtBJib2JA\n" +
            "cGdwYWlubGVzcy5vcmeIjwQTFgoAQQUCYksu1gkQJh5QgZc2xJMWIQSg0vMWD2ss\n" +
            "5XpQ/zImHlCBlzbEkwKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAADvrAD/cWBW\n" +
            "mRkSfoCbEl22s59FXE7NPENrsJK8jxmWsWX3jbEA/AyXMCjwH6IhDgdgO7wH2z1r\n" +
            "cUb/hokiCcCaJs6hjKcInF0EYksu1hIKKwYBBAGXVQEFAQEHQCeURSBi9brhisUH\n" +
            "Dz0xN1NCgU5yeirx53xrQDFFx+d6AwEIBwAA/1GHX9+4Rg0ePsXGm1QIWL+C4rdf\n" +
            "AReCTYoS3EBiZVdADoyIdQQYFgoAHQUCYksu1gKeAQKbDAUWAgMBAAQLCQgHBRUK\n" +
            "CQgLAAoJECYeUIGXNsST8c0A/1dEIO9gsFB15UWDlTzN3S0TXQNN8wVzIMdW7XP2\n" +
            "7c6bAQCB5ChqQA9AB1020DLr28BAbSjI7mPdIWg2PpE7B1EXC5xYBGJLLtYWCSsG\n" +
            "AQQB2kcPAQEHQKP5NxT0ZhmRbrl3S6uwrUN248g1TEUR0DCVuLgyGSLpAAEA6bMa\n" +
            "GaUf3S55rkFDjFC4Cv72zc8E5ex2RKgbpxXxqhYQN4jVBBgWCgB9BQJiSy7WAp4B\n" +
            "ApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUCYksu1gAKCRDJLjPCA2NIfylD\n" +
            "AP4tNFV23FBlrC57iesHVc+TTfNJ8rd+U7mbJvUgykcSNAEAy64tKPuVj+aA1bpm\n" +
            "gHxfqdEJCOko8UhVVP6ltiDUcAoACgkQJh5QgZc2xJP9TQEA1DNgFno3di+xGDEN\n" +
            "pwe9lmz8d/RWy/kuBT9S/3CMJjQBAKNBhHPuFfvk7RFbsmMrHsSqDFqIuUfGqq39\n" +
            "VzmiMp8N\n" +
            "=LpkJ\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    private static final String BOB_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: A0D2 F316 0F6B 2CE5 7A50  FF32 261E 5081 9736 C493\n" +
            "Comment: bob@pgpainless.org\n" +
            "\n" +
            "mDMEYksu1hYJKwYBBAHaRw8BAQdAXTBT1OKN1GAvGC+fzuy/k34BK+d5Saa87Glb\n" +
            "iQgIxg+0EmJvYkBwZ3BhaW5sZXNzLm9yZ4iPBBMWCgBBBQJiSy7WCRAmHlCBlzbE\n" +
            "kxYhBKDS8xYPayzlelD/MiYeUIGXNsSTAp4BApsBBRYCAwEABAsJCAcFFQoJCAsC\n" +
            "mQEAAO+sAP9xYFaZGRJ+gJsSXbazn0VcTs08Q2uwkryPGZaxZfeNsQD8DJcwKPAf\n" +
            "oiEOB2A7vAfbPWtxRv+GiSIJwJomzqGMpwi4OARiSy7WEgorBgEEAZdVAQUBAQdA\n" +
            "J5RFIGL1uuGKxQcPPTE3U0KBTnJ6KvHnfGtAMUXH53oDAQgHiHUEGBYKAB0FAmJL\n" +
            "LtYCngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRAmHlCBlzbEk/HNAP9XRCDvYLBQ\n" +
            "deVFg5U8zd0tE10DTfMFcyDHVu1z9u3OmwEAgeQoakAPQAddNtAy69vAQG0oyO5j\n" +
            "3SFoNj6ROwdRFwu4MwRiSy7WFgkrBgEEAdpHDwEBB0Cj+TcU9GYZkW65d0ursK1D\n" +
            "duPINUxFEdAwlbi4Mhki6YjVBBgWCgB9BQJiSy7WAp4BApsCBRYCAwEABAsJCAcF\n" +
            "FQoJCAtfIAQZFgoABgUCYksu1gAKCRDJLjPCA2NIfylDAP4tNFV23FBlrC57iesH\n" +
            "Vc+TTfNJ8rd+U7mbJvUgykcSNAEAy64tKPuVj+aA1bpmgHxfqdEJCOko8UhVVP6l\n" +
            "tiDUcAoACgkQJh5QgZc2xJP9TQEA1DNgFno3di+xGDENpwe9lmz8d/RWy/kuBT9S\n" +
            "/3CMJjQBAKNBhHPuFfvk7RFbsmMrHsSqDFqIuUfGqq39VzmiMp8N\n" +
            "=1MqZ\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    /**
     * In this example, Alice is sending a signed and encrypted message to Bob.
     * She signs the message using her key and then encrypts the message to both bobs certificate and her own.
     * <p>
     * Bob subsequently decrypts the message using his key and verifies that the message was signed by Alice using
     * her certificate.
     */
    @Test
    public void encryptAndSignMessage() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        // Prepare keys
        OpenPGPKeyReader reader = api.readKey();
        OpenPGPKey keyAlice = reader.parseKey(ALICE_KEY);
        OpenPGPCertificate certificateAlice = reader.parseCertificate(ALICE_CERT);
        SecretKeyRingProtector protectorAlice = SecretKeyRingProtector.unprotectedKeys();

        OpenPGPKey keyBob = reader.parseKey(BOB_KEY);
        OpenPGPCertificate certificateBob = reader.parseCertificate(BOB_CERT);
        SecretKeyRingProtector protectorBob = SecretKeyRingProtector.unprotectedKeys();

        // plaintext message to encrypt
        String message = "Hello, World!\n";
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        // Encrypt and sign
        EncryptionStream encryptor = api.generateMessage()
                .onOutputStream(ciphertext)
                .withOptions(ProducerOptions.signAndEncrypt(
                                // we want to encrypt communication (affects key selection based on key flags)
                                EncryptionOptions.encryptCommunications(api)
                                        .addRecipient(certificateBob)
                                        .addRecipient(certificateAlice),
                                SigningOptions.get(api)
                                        .addInlineSignature(protectorAlice, keyAlice, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                        ).setAsciiArmor(true)
                );

        // Pipe data trough and CLOSE the stream (important)
        Streams.pipeAll(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), encryptor);
        encryptor.close();
        String encryptedMessage = ciphertext.toString();

        // Decrypt and verify signatures
        DecryptionStream decryptor = api.processMessage()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes(StandardCharsets.UTF_8)))
                .withOptions(ConsumerOptions.get(api)
                        .addDecryptionKey(keyBob, protectorBob)
                        .addVerificationCert(certificateAlice)
                );

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, plaintext);
        decryptor.close();

        // Check the metadata to see how the message was encrypted/signed
        MessageMetadata metadata = decryptor.getMetadata();
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerifiedSignedBy(certificateAlice));
        assertEquals(message, plaintext.toString());
    }

    /**
     * This example demonstrates how to encrypt and decrypt a message using a passphrase.
     * This method can be combined with public key based encryption and signing.
     */
    @Test
    public void encryptUsingPassphrase() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        String message = "Hello, World!";
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        // Encrypt
        EncryptionStream encryptor = api.generateMessage()
                .onOutputStream(ciphertext)
                .withOptions(ProducerOptions
                        .encrypt(EncryptionOptions.encryptCommunications(api)
                                .addMessagePassphrase(Passphrase.fromPassword("p4ssphr4s3"))
                        ).setAsciiArmor(true)
                );

        Streams.pipeAll(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), encryptor);
        encryptor.close();

        String asciiCiphertext = ciphertext.toString();

        // Decrypt
        DecryptionStream decryptor = api.processMessage()
                .onInputStream(new ByteArrayInputStream(asciiCiphertext.getBytes(StandardCharsets.UTF_8)))
                .withOptions(ConsumerOptions.get(api).addMessagePassphrase(Passphrase.fromPassword("p4ssphr4s3")));

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        Streams.pipeAll(decryptor, plaintext);

        decryptor.close();

        assertEquals(message, plaintext.toString());
    }

    /**
     * In this example, Alice is sending a signed and encrypted message to Bob.
     * She encrypts the message to both bobs certificate and her own.
     * A multiline comment header is added using the fluent ProducerOption syntax.
     * <p>
     * Bob subsequently decrypts the message using his key.
     */
    @Test
    public void encryptWithCommentHeader() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        // Prepare keys
        OpenPGPKeyReader reader = api.readKey();
        OpenPGPCertificate certificateAlice = reader.parseCertificate(ALICE_CERT);

        OpenPGPKey keyBob = reader.parseKey(BOB_KEY);
        OpenPGPCertificate certificateBob = reader.parseCertificate(BOB_CERT);
        SecretKeyRingProtector protectorBob = SecretKeyRingProtector.unprotectedKeys();

        // plaintext message to encrypt
        String message = "Hello, World!\n";
        String[] comments = {
                "This comment was added using options.",
                "And it has three lines.",
                " ",
                "Empty lines are skipped."
        };
        String comment = comments[0] + "\n" + comments[1] + "\n" + comments[2] + "\n" + comments[3];
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        // Encrypt and sign
        EncryptionStream encryptor = api.generateMessage()
                .onOutputStream(ciphertext)
                .withOptions(ProducerOptions.encrypt(
                                        // we want to encrypt communication (affects key selection based on key flags)
                                        EncryptionOptions.encryptCommunications(api)
                                                .addRecipient(certificateBob)
                                                .addRecipient(certificateAlice)
                                ).setAsciiArmor(true)
                                .setComment(comment)
                );

        // Pipe data trough and CLOSE the stream (important)
        Streams.pipeAll(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), encryptor);
        encryptor.close();
        String encryptedMessage = ciphertext.toString();

        // check that comment header was added after "BEGIN PGP" and "Version:"
        assertEquals(encryptedMessage.split("\n")[2].trim(), "Comment: " + comments[0]);
        assertEquals(encryptedMessage.split("\n")[3].trim(), "Comment: " + comments[1]);
        assertEquals(encryptedMessage.split("\n")[4].trim(), "Comment: " + comments[3]);

        // also test, that decryption still works...

        // Decrypt and verify signatures
        DecryptionStream decryptor = api.processMessage()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes(StandardCharsets.UTF_8)))
                .withOptions(ConsumerOptions.get(api)
                        .addDecryptionKey(keyBob, protectorBob)
                        .addVerificationCert(certificateAlice)
                );

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, plaintext);
        decryptor.close();

        // Check the metadata to see how the message was encrypted/signed
        MessageMetadata metadata = decryptor.getMetadata();
        assertTrue(metadata.isEncrypted());
        assertEquals(message, plaintext.toString());
    }
}
