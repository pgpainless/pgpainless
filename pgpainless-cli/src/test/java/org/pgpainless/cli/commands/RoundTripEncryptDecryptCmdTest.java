// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;

public class RoundTripEncryptDecryptCmdTest extends CLITest {

    public RoundTripEncryptDecryptCmdTest() {
        super(LoggerFactory.getLogger(RoundTripEncryptDecryptCmdTest.class));
    }

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: A2EC 077F C977 E15D D799  EFF9 2C0D 3C12 3CF5 1C08\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEY2veRhYJKwYBBAHaRw8BAQdAeJYBoCcnGPQ3nchyyBrWQ83q3hqJnfZn2mqh\n" +
            "d1M7WwsAAP0R1ELnfdJhXcfjaYPLHzwy1i34FxP5g3tvdgg9Q7VmchActBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEFAmNr3kYJECwNPBI89RwI\n" +
            "FiEEouwHf8l34V3Xme/5LA08Ejz1HAgCngECmwEFFgIDAQAECwkIBwUVCgkICwKZ\n" +
            "AQAAe6YA/2sO483Vi2Fgs4ejv8FykyO96IVrMoYhw3Od4LyWEyDfAQDi15LxJJm6\n" +
            "T2sXdENVigdwDJiELxjOtbmivuJutxkWCJxdBGNr3kYSCisGAQQBl1UBBQEBB0CS\n" +
            "zXjySHqlicxG3QlrVeTIqwKitL1sWsx0MCDmT1C8dAMBCAcAAP9VNkfMQvYAlYSP\n" +
            "aYEkwEOc8/XpiloVKtPzxwVCPlXFeBDCiHUEGBYKAB0FAmNr3kYCngECmwwFFgID\n" +
            "AQAECwkIBwUVCgkICwAKCRAsDTwSPPUcCOT4AQDZcN5a/e8Qr+LNBIyXXLgJWGsL\n" +
            "59nsKHBbDURnxbEnMQEAybS8u+Rsb82yW4CfaA4CLRTC3eDc5Y4QwYWzLogWNwic\n" +
            "WARja95GFgkrBgEEAdpHDwEBB0DcdwQufWLq6ASku4JWBBd9JplRVhK0cXWuTE73\n" +
            "uWltuwABAI0bVQXvgDnxTs6kUO7JIWtokM5lI/1bfG4L1YOfnXIgD7CI1QQYFgoA\n" +
            "fQUCY2veRgKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmNr3kYACgkQ\n" +
            "7NC/hj9lyaWVAwEA3ze1LCi1reGfB5tS3Au6A8aalyk4UV0iVOXxwV5r+E4BAJGz\n" +
            "ZMFF/iQ/rOcSAsHPp4ggezZALDIkT2Hrn6iLDdsLAAoJECwNPBI89RwIuBIBAMxG\n" +
            "u/s4maOFozcO4JoCZTsLHGy70SG6UuVQjK0EyJJ1APoDEfK+qTlC7/FoijMA6Ew9\n" +
            "aesZ2IHgpwA7jlyHSgwLDw==\n" +
            "=H3HU\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: A2EC 077F C977 E15D D799  EFF9 2C0D 3C12 3CF5 1C08\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "mDMEY2veRhYJKwYBBAHaRw8BAQdAeJYBoCcnGPQ3nchyyBrWQ83q3hqJnfZn2mqh\n" +
            "d1M7Wwu0HEFsaWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz6IjwQTFgoAQQUCY2ve\n" +
            "RgkQLA08Ejz1HAgWIQSi7Ad/yXfhXdeZ7/ksDTwSPPUcCAKeAQKbAQUWAgMBAAQL\n" +
            "CQgHBRUKCQgLApkBAAB7pgD/aw7jzdWLYWCzh6O/wXKTI73ohWsyhiHDc53gvJYT\n" +
            "IN8BAOLXkvEkmbpPaxd0Q1WKB3AMmIQvGM61uaK+4m63GRYIuDgEY2veRhIKKwYB\n" +
            "BAGXVQEFAQEHQJLNePJIeqWJzEbdCWtV5MirAqK0vWxazHQwIOZPULx0AwEIB4h1\n" +
            "BBgWCgAdBQJja95GAp4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQLA08Ejz1HAjk\n" +
            "+AEA2XDeWv3vEK/izQSMl1y4CVhrC+fZ7ChwWw1EZ8WxJzEBAMm0vLvkbG/NsluA\n" +
            "n2gOAi0Uwt3g3OWOEMGFsy6IFjcIuDMEY2veRhYJKwYBBAHaRw8BAQdA3HcELn1i\n" +
            "6ugEpLuCVgQXfSaZUVYStHF1rkxO97lpbbuI1QQYFgoAfQUCY2veRgKeAQKbAgUW\n" +
            "AgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmNr3kYACgkQ7NC/hj9lyaWVAwEA3ze1\n" +
            "LCi1reGfB5tS3Au6A8aalyk4UV0iVOXxwV5r+E4BAJGzZMFF/iQ/rOcSAsHPp4gg\n" +
            "ezZALDIkT2Hrn6iLDdsLAAoJECwNPBI89RwIuBIBAMxGu/s4maOFozcO4JoCZTsL\n" +
            "HGy70SG6UuVQjK0EyJJ1APoDEfK+qTlC7/FoijMA6Ew9aesZ2IHgpwA7jlyHSgwL\n" +
            "Dw==\n" +
            "=c1PZ\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @Test
    public void encryptAndDecryptAMessage() throws IOException {
        // Juliets key and cert
        File julietKeyFile = pipeStdoutToFile("juliet.key");
        assertSuccess(executeCommand("generate-key", "Juliet <juliet@capulet.lit>"));

        pipeFileToStdin(julietKeyFile);
        File julietCertFile = pipeStdoutToFile("juliet.cert");
        assertSuccess(executeCommand("extract-cert"));

        // Romeos key and cert
        File romeoKeyFile = pipeStdoutToFile("romeo.key");
        assertSuccess(executeCommand("generate-key", "Romeo <romeo@montague.lit>"));

        File romeoCertFile = pipeStdoutToFile("romeo.cert");
        pipeFileToStdin(romeoKeyFile);
        assertSuccess(executeCommand("extract-cert"));

        // Romeo encrypts signs and encrypts for Juliet and himself
        String msg = "Hello World!\n";
        File encryptedMessageFile = pipeStdoutToFile("msg.asc");
        pipeStringToStdin(msg);
        assertSuccess(executeCommand("encrypt", "--sign-with", romeoKeyFile.getAbsolutePath(),
                julietCertFile.getAbsolutePath(), romeoCertFile.getAbsolutePath()));

        // Juliet can decrypt and verify with Romeos cert
        pipeFileToStdin(encryptedMessageFile);
        File verificationsFile = nonExistentFile("verifications");
        ByteArrayOutputStream decrypted = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--verifications-out", verificationsFile.getAbsolutePath(),
                "--verify-with", romeoCertFile.getAbsolutePath(),
                julietKeyFile.getAbsolutePath()));
        assertEquals(msg, decrypted.toString());

        // Romeo can decrypt and verify too
        pipeFileToStdin(encryptedMessageFile);
        File anotherVerificationsFile = nonExistentFile("anotherVerifications");
        decrypted = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--verifications-out", anotherVerificationsFile.getAbsolutePath(),
                "--verify-with", romeoCertFile.getAbsolutePath(),
                romeoKeyFile.getAbsolutePath()));
        assertEquals(msg, decrypted.toString());

        String julietsVerif = readStringFromFile(verificationsFile);
        String romeosVerif = readStringFromFile(anotherVerificationsFile);
        assertEquals(julietsVerif, romeosVerif);
        assertFalse(julietsVerif.isEmpty());
        assertEquals(115, julietsVerif.length()); // 115 is number of symbols in [DATE, FINGER, FINGER, MODE] for V4
    }

    @Test
    public void testMissingArgumentsIfNoArgsSupplied() throws IOException {
        int exit = executeCommand("encrypt");
        assertEquals(SOPGPException.MissingArg.EXIT_CODE, exit);
    }

    @Test
    @Disabled("Disabled, since we now read certificates from secret keys")
    public void testEncryptingForKeyFails() throws IOException {
        File notACert = writeFile("key.asc", KEY);

        pipeStringToStdin("Hello, World!");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("encrypt", notACert.getAbsolutePath());
        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testEncrypt_SignWithCertFails() throws IOException {
        File cert = writeFile("cert.asc", CERT);
        // noinspection UnnecessaryLocalVariable
        File notAKey = cert;

        pipeStringToStdin("Hello, World!");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("encrypt", "--sign-with", notAKey.getAbsolutePath(), cert.getAbsolutePath());
        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testDecryptVerifyOut_withoutVerifyWithFails() throws IOException {
        File key = writeFile("key.asc", KEY);

        File verifications = nonExistentFile("verifications");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("decrypt", "--verifications-out",
                verifications.getAbsolutePath(), key.getAbsolutePath());

        assertEquals(SOPGPException.IncompleteVerification.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testVerificationsOutAlreadyExistFails() throws IOException {
        File key = writeFile("key.asc", KEY);
        File cert = writeFile("cert.asc", CERT);

        File verifications = writeFile("verifications", "this file is not empty");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("decrypt", "--verify-with", cert.getAbsolutePath(),
                "--verifications-out", verifications.getAbsolutePath(),
                key.getAbsolutePath());

        assertEquals(SOPGPException.OutputExists.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testSessionKeyOutWritesSessionKeyOut() throws IOException {
        File key = writeFile("key.asc", KEY);
        File sessionKeyFile = nonExistentFile("session.key");

        String plaintext = "Hello, World!\n";
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdAYisjZTDRm217LHQbqjB766tm62CKTkRj3Gd0wYxVRCgw\n" +
                "48SnOJINCJoPgDsxk2NiJmLCImoiET7IElqxN9htdDXQJwcRK+71r/ZyO4YJpWuX\n" +
                "0sAAAcEFc3nT+un31sOi8KoBJlc5n+MemntQvcWDs8B87BEW/Ncjrs0s4pJpZKBQ\n" +
                "/AWc4wLCI3ylfMQJB2pICqaOO3KP3WepgTIw5fuZm6YfriKQi7uZvVx1N+uaCIoa\n" +
                "K2IVVf/7O9KZJ9GbsGYdpBj9IdaIZiVS3Xi8rwgQl3haI/EeHC3nnCsWyj23Fjt3\n" +
                "LjbMqpHbSnp8U1cQ8rXavrREaKv69PFeJio6/hRg32TzJqn05dPALRxHMEkxxa4h\n" +
                "FpVU\n" +
                "=edS5\n" +
                "-----END PGP MESSAGE-----";
        String sessionKey = "9:B6FAD96B7ED2DA27D8A36EAEA75DAB7AC587180B14D8A24BD7263524F3DDECC3\n";

        pipeStringToStdin(ciphertext);
        ByteArrayOutputStream plaintextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--session-key-out",
                sessionKeyFile.getAbsolutePath(), key.getAbsolutePath()));

        assertEquals(plaintext, plaintextOut.toString());
        String resultSessionKey = readStringFromFile(sessionKeyFile);
        assertEquals(sessionKey, resultSessionKey);
    }

    @Test
    public void decryptMessageWithSessionKey() throws IOException {
        String plaintext = "Hello, World!\n";
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdAYisjZTDRm217LHQbqjB766tm62CKTkRj3Gd0wYxVRCgw\n" +
                "48SnOJINCJoPgDsxk2NiJmLCImoiET7IElqxN9htdDXQJwcRK+71r/ZyO4YJpWuX\n" +
                "0sAAAcEFc3nT+un31sOi8KoBJlc5n+MemntQvcWDs8B87BEW/Ncjrs0s4pJpZKBQ\n" +
                "/AWc4wLCI3ylfMQJB2pICqaOO3KP3WepgTIw5fuZm6YfriKQi7uZvVx1N+uaCIoa\n" +
                "K2IVVf/7O9KZJ9GbsGYdpBj9IdaIZiVS3Xi8rwgQl3haI/EeHC3nnCsWyj23Fjt3\n" +
                "LjbMqpHbSnp8U1cQ8rXavrREaKv69PFeJio6/hRg32TzJqn05dPALRxHMEkxxa4h\n" +
                "FpVU\n" +
                "=edS5\n" +
                "-----END PGP MESSAGE-----";
        String sessionKey = "9:B6FAD96B7ED2DA27D8A36EAEA75DAB7AC587180B14D8A24BD7263524F3DDECC3\n";

        File sessionKeyFile = writeFile("session.key", sessionKey);

        pipeStringToStdin(ciphertext);
        ByteArrayOutputStream plaintextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--with-session-key", sessionKeyFile.getAbsolutePath()));

        assertEquals(plaintext, plaintextOut.toString());
    }

    @Test
    public void testDecryptWithSessionKeyVerifyWithYieldsExpectedVerifications() throws IOException {
        String plaintext = "Hello, World!\n";
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdAYisjZTDRm217LHQbqjB766tm62CKTkRj3Gd0wYxVRCgw\n" +
                "48SnOJINCJoPgDsxk2NiJmLCImoiET7IElqxN9htdDXQJwcRK+71r/ZyO4YJpWuX\n" +
                "0sAAAcEFc3nT+un31sOi8KoBJlc5n+MemntQvcWDs8B87BEW/Ncjrs0s4pJpZKBQ\n" +
                "/AWc4wLCI3ylfMQJB2pICqaOO3KP3WepgTIw5fuZm6YfriKQi7uZvVx1N+uaCIoa\n" +
                "K2IVVf/7O9KZJ9GbsGYdpBj9IdaIZiVS3Xi8rwgQl3haI/EeHC3nnCsWyj23Fjt3\n" +
                "LjbMqpHbSnp8U1cQ8rXavrREaKv69PFeJio6/hRg32TzJqn05dPALRxHMEkxxa4h\n" +
                "FpVU\n" +
                "=edS5\n" +
                "-----END PGP MESSAGE-----";
        String sessionKey = "9:B6FAD96B7ED2DA27D8A36EAEA75DAB7AC587180B14D8A24BD7263524F3DDECC3\n";

        File cert = writeFile("cert.asc", CERT);
        File sessionKeyFile = writeFile("session.key", sessionKey);
        File verifications = nonExistentFile("verifications");

        pipeStringToStdin(ciphertext);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--with-session-key", sessionKeyFile.getAbsolutePath(),
                "--verify-with", cert.getAbsolutePath(), "--verifications-out", verifications.getAbsolutePath()));

        assertEquals(plaintext, out.toString());
        String verificationString = readStringFromFile(verifications);
        assertEquals("2022-11-09T17:22:48Z C0DCEC44B1A173664B05DABCECD0BF863F65C9A5 A2EC077FC977E15DD799EFF92C0D3C123CF51C08 mode:binary\n",
                verificationString);
    }

    @Test
    public void encryptAndDecryptMessageWithPassphrase() throws IOException {
        File passwordFile = writeFile("password", "c1tiz€n4");
        String message = "I cannot think of meaningful messages for test vectors rn";

        pipeStringToStdin(message);
        ByteArrayOutputStream ciphertext = pipeStdoutToStream();
        assertSuccess(executeCommand("encrypt", "--with-password", passwordFile.getAbsolutePath()));

        String ciphertextString = ciphertext.toString();
        assertTrue(ciphertextString.startsWith("-----BEGIN PGP MESSAGE-----\n"));

        pipeBytesToStdin(ciphertext.toByteArray());
        ByteArrayOutputStream plaintext = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--with-password", passwordFile.getAbsolutePath()));

        assertEquals(message, plaintext.toString());
    }

    @Test
    public void testEncryptWithIncapableCert() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .addUserId("No Crypt <no@crypt.key>")
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519),
                        KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .build()
                .getPGPSecretKeyRing();
        PGPPublicKeyRing cert = PGPainless.extractCertificate(secretKeys);
        File certFile = writeFile("cert.pgp", cert.getEncoded());

        pipeStringToStdin("Hello, World!\n");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("encrypt", certFile.getAbsolutePath());

        assertEquals(SOPGPException.CertCannotEncrypt.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testSignWithIncapableKey()
            throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .addUserId("Cannot Sign <cannot@sign.key>")
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .build()
                .getPGPSecretKeyRing();
        File keyFile = writeFile("key.pgp", secretKeys.getEncoded());
        File certFile = writeFile("cert.pgp", PGPainless.extractCertificate(secretKeys).getEncoded());

        pipeStringToStdin("Hello, World!\n");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("encrypt", "--sign-with", keyFile.getAbsolutePath(),
                certFile.getAbsolutePath());

        assertEquals(SOPGPException.KeyCannotSign.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testEncryptDecryptRoundTripWithPasswordProtectedKey() throws IOException {
        // generate password protected key
        File passwordFile = writeFile("password", "fooBarBaz420");
        File keyFile = pipeStdoutToFile("key.asc");
        assertSuccess(executeCommand("generate-key",
                "--with-key-password", passwordFile.getAbsolutePath(),
                "Pascal Password <pascal@password.protected>"));

        // extract cert
        File certFile = pipeStdoutToFile("cert.asc");
        pipeFileToStdin(keyFile);
        assertSuccess(executeCommand("extract-cert"));

        // encrypt and sign message
        String msg = "Hello, World!\n";
        pipeStringToStdin(msg);
        File encryptedFile = pipeStdoutToFile("msg.asc");
        assertSuccess(executeCommand("encrypt",
                "--sign-with", keyFile.getAbsolutePath(),
                "--with-key-password", passwordFile.getAbsolutePath(),
                "--no-armor",
                "--as", "binary",
                certFile.getAbsolutePath()));

        // Decrypt
        File verificationsFile = nonExistentFile("verifications");
        pipeFileToStdin(encryptedFile);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt",
                "--verify-with", certFile.getAbsolutePath(),
                "--verifications-out", verificationsFile.getAbsolutePath(),
                "--with-key-password", passwordFile.getAbsolutePath(),
                keyFile.getAbsolutePath()));

        assertEquals(msg, out.toString());
    }

    @Test
    public void decryptGarbageFails() throws IOException {
        File keyFile = writeFile("key.asc", KEY);
        pipeStringToStdin("Some Garbage!");
        int exitCode = executeCommand("decrypt", keyFile.getAbsolutePath());
        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
    }

    @Test
    public void decryptMessageWithWrongKeyFails() throws IOException {
        File keyFile = pipeStdoutToFile("key.asc");
        assertSuccess(executeCommand("generate-key", "Bob <bob@pgpainless.org>"));
        // message was *not* created with key above
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdAYisjZTDRm217LHQbqjB766tm62CKTkRj3Gd0wYxVRCgw\n" +
                "48SnOJINCJoPgDsxk2NiJmLCImoiET7IElqxN9htdDXQJwcRK+71r/ZyO4YJpWuX\n" +
                "0sAAAcEFc3nT+un31sOi8KoBJlc5n+MemntQvcWDs8B87BEW/Ncjrs0s4pJpZKBQ\n" +
                "/AWc4wLCI3ylfMQJB2pICqaOO3KP3WepgTIw5fuZm6YfriKQi7uZvVx1N+uaCIoa\n" +
                "K2IVVf/7O9KZJ9GbsGYdpBj9IdaIZiVS3Xi8rwgQl3haI/EeHC3nnCsWyj23Fjt3\n" +
                "LjbMqpHbSnp8U1cQ8rXavrREaKv69PFeJio6/hRg32TzJqn05dPALRxHMEkxxa4h\n" +
                "FpVU\n" +
                "=edS5\n" +
                "-----END PGP MESSAGE-----";

        pipeStringToStdin(ciphertext);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("decrypt", keyFile.getAbsolutePath());
        assertEquals(SOPGPException.CannotDecrypt.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void encryptWithPasswordADecryptWithPasswordBFails() throws IOException {
        File password1 = writeFile("password1", "swordfish");
        File password2 = writeFile("password2", "orange");

        pipeStringToStdin("Bonjour, le monde!\n");
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("encrypt", "--with-password", password1.getAbsolutePath()));

        pipeBytesToStdin(ciphertextOut.toByteArray());
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("decrypt", "--with-password", password2.getAbsolutePath());
        assertEquals(SOPGPException.CannotDecrypt.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void encryptWithGarbageCertFails() throws IOException {
        File garbageCert = writeFile("cert.asc", "This is garbage!");

        pipeStringToStdin("Hallo, Welt!\n");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("encrypt", garbageCert.getAbsolutePath());

        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void encrypt_signWithGarbageKeyFails() throws IOException {
        File cert = writeFile("cert.asc", CERT);
        File garbageKey = writeFile("key.asc", "This is not a key!");

        pipeStringToStdin("Salut!\n");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("encrypt", "--sign-with", garbageKey.getAbsolutePath(),
                cert.getAbsolutePath());

        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void decrypt_withGarbageKeyFails() throws IOException {
        File key = writeFile("key.asc", "this is garbage");
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdAYisjZTDRm217LHQbqjB766tm62CKTkRj3Gd0wYxVRCgw\n" +
                "48SnOJINCJoPgDsxk2NiJmLCImoiET7IElqxN9htdDXQJwcRK+71r/ZyO4YJpWuX\n" +
                "0sAAAcEFc3nT+un31sOi8KoBJlc5n+MemntQvcWDs8B87BEW/Ncjrs0s4pJpZKBQ\n" +
                "/AWc4wLCI3ylfMQJB2pICqaOO3KP3WepgTIw5fuZm6YfriKQi7uZvVx1N+uaCIoa\n" +
                "K2IVVf/7O9KZJ9GbsGYdpBj9IdaIZiVS3Xi8rwgQl3haI/EeHC3nnCsWyj23Fjt3\n" +
                "LjbMqpHbSnp8U1cQ8rXavrREaKv69PFeJio6/hRg32TzJqn05dPALRxHMEkxxa4h\n" +
                "FpVU\n" +
                "=edS5\n" +
                "-----END PGP MESSAGE-----";

        pipeStringToStdin(ciphertext);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("decrypt", key.getAbsolutePath());

        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void decrypt_verifyWithGarbageCertFails() throws IOException {
        File key = writeFile("key.asc", KEY);
        File cert = writeFile("cert.asc", "now this is garbage");
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdAYisjZTDRm217LHQbqjB766tm62CKTkRj3Gd0wYxVRCgw\n" +
                "48SnOJINCJoPgDsxk2NiJmLCImoiET7IElqxN9htdDXQJwcRK+71r/ZyO4YJpWuX\n" +
                "0sAAAcEFc3nT+un31sOi8KoBJlc5n+MemntQvcWDs8B87BEW/Ncjrs0s4pJpZKBQ\n" +
                "/AWc4wLCI3ylfMQJB2pICqaOO3KP3WepgTIw5fuZm6YfriKQi7uZvVx1N+uaCIoa\n" +
                "K2IVVf/7O9KZJ9GbsGYdpBj9IdaIZiVS3Xi8rwgQl3haI/EeHC3nnCsWyj23Fjt3\n" +
                "LjbMqpHbSnp8U1cQ8rXavrREaKv69PFeJio6/hRg32TzJqn05dPALRxHMEkxxa4h\n" +
                "FpVU\n" +
                "=edS5\n" +
                "-----END PGP MESSAGE-----";
        File verificationsFile = nonExistentFile("verifications");

        pipeStringToStdin(ciphertext);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("decrypt", key.getAbsolutePath(),
                "--verify-with", cert.getAbsolutePath(),
                "--verifications-out", verificationsFile.getAbsolutePath());

        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void encryptWithProtectedKey_wrongPassphraseFails() throws IOException {
        File password = writeFile("passphrase1", "orange");
        File wrongPassword = writeFile("passphrase2", "blue");

        File keyFile = pipeStdoutToFile("key.asc");
        assertSuccess(executeCommand("generate-key", "Pedro <pedro@pgpainless.org>",
                "--with-key-password", password.getAbsolutePath()));

        File certFile = pipeStdoutToFile("cert.asc");
        pipeFileToStdin(keyFile);
        assertSuccess(executeCommand("extract-cert"));

        // Use no passphrase to unlock the key
        String msg = "Guten Tag, Welt!\n";
        pipeStringToStdin(msg);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("encrypt", "--sign-with", keyFile.getAbsolutePath(),
                certFile.getAbsolutePath());
        assertEquals(SOPGPException.KeyIsProtected.EXIT_CODE, exitCode);
        assertEquals(0, out.size());

        // use wrong passphrase to unlock key when signing message
        pipeStringToStdin("Guten Tag, Welt!\n");
        out = pipeStdoutToStream();
        exitCode = executeCommand("encrypt", "--sign-with", keyFile.getAbsolutePath(),
                "--with-key-password", wrongPassword.getAbsolutePath(),
                certFile.getAbsolutePath());
        assertEquals(SOPGPException.KeyIsProtected.EXIT_CODE, exitCode);
        assertEquals(0, out.size());

        // use correct passphrase and encrypt+sign message
        pipeStringToStdin("Guten Tag, Welt!\n");
        out = pipeStdoutToStream();
        assertSuccess(executeCommand("encrypt", "--sign-with", keyFile.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath(),
                certFile.getAbsolutePath()));
        String ciphertext = out.toString();

        // Use no passphrase to decrypt key when decrypting
        pipeStringToStdin(ciphertext);
        out = pipeStdoutToStream();
        exitCode = executeCommand("decrypt", keyFile.getAbsolutePath());
        assertEquals(SOPGPException.KeyIsProtected.EXIT_CODE, exitCode);
        assertEquals(0, out.size());

        // Use wrong passphrase to decrypt key when decrypting
        pipeStringToStdin(ciphertext);
        out = pipeStdoutToStream();
        exitCode = executeCommand("decrypt", "--with-key-password", wrongPassword.getAbsolutePath(),
                keyFile.getAbsolutePath());
        assertEquals(SOPGPException.KeyIsProtected.EXIT_CODE, exitCode);
        assertEquals(0, out.size());

        // User correct passphrase to decrypt key when decrypting
        pipeStringToStdin(ciphertext);
        out = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--with-key-password", password.getAbsolutePath(),
                keyFile.getAbsolutePath()));
        assertEquals(msg, out.toString());
    }

    @Test
    public void decryptMalformedMessageYieldsBadData() throws IOException {
        // Message contains encrypted data packet which contains the plaintext directly - no literal data packet.
        // It is therefore malformed.
        String malformed = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.72b04\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdApKA6VDKSLQvwS2kbWqlhcXD8XHdFkSccqv5tBptZnBgw\n" +
                "nZNXVhwUpap0ymb4jPTD+EVPKOfPyy04ouIGZAJKkfYDeSL/8sKcbnPPuQJYYjGQ\n" +
                "ySDNmidrtTonwcSuwAfRyn74BBqOVhrr8GXkVIfevIlZFQ==\n" +
                "=wIgl\n" +
                "-----END PGP MESSAGE-----";
        File key = writeFile("key.asc", KEY);
        pipeStringToStdin(malformed);
        int exitCode = executeCommand("decrypt", key.getAbsolutePath());
        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
    }

    @Test
    public void decryptWithPasswordWithPendingWhitespaceWorks() throws IOException {
        assertEncryptWithPasswordADecryptWithPasswordBWorks("sw0rdf1sh", "sw0rdf1sh \n");
    }

    @Test
    public void encryptWithTrailingWhitespaceDecryptWithoutWorks() throws IOException {
        assertEncryptWithPasswordADecryptWithPasswordBWorks("sw0rdf1sh \n", "sw0rdf1sh");
    }

    @Test
    public void decryptWithWhitespacePasswordWorks() throws IOException {
        // is encrypted for "sw0rdf1sh \n"
        String encryptedToPasswordWithTrailingWhitespace = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "jA0ECQMC32tEJug0BCpg0kABfT3dKgA4K8XGpk2ul67BXLZD//fCCSmIQIWnNhE1\n" +
                "6q97xFQ628K8f/58+XoBzLqLDT+LEz9Bz+Yg9QfzkEFy\n" +
                "=2Y+K\n" +
                "-----END PGP MESSAGE-----";
        pipeStringToStdin(encryptedToPasswordWithTrailingWhitespace);
        File password = writeFile("password", "sw0rdf1sh \n");
        ByteArrayOutputStream plaintext = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--with-password", password.getAbsolutePath()));

        assertEquals("Hello, World!\n", plaintext.toString());
    }

    private void assertEncryptWithPasswordADecryptWithPasswordBWorks(String passwordA, String passwordB)
            throws IOException {
        File passwordAFile = writeFile("password", passwordA);
        File passwordBFile = writeFile("passwordWithWS", passwordB);

        String msg = "Hello, World!\n";
        pipeStringToStdin(msg);
        ByteArrayOutputStream ciphertext = pipeStdoutToStream();
        assertSuccess(executeCommand("encrypt", "--with-password", passwordAFile.getAbsolutePath()));

        pipeStringToStdin(ciphertext.toString());
        ByteArrayOutputStream plaintext = pipeStdoutToStream();
        assertSuccess(executeCommand("decrypt", "--with-password", passwordBFile.getAbsolutePath()));

        assertEquals(msg, plaintext.toString());
    }

    @Test
    public void testDecryptWithoutDecryptionOptionFails() throws IOException {
        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4D831k4umlLu4SAQdAYisjZTDRm217LHQbqjB766tm62CKTkRj3Gd0wYxVRCgw\n" +
                "48SnOJINCJoPgDsxk2NiJmLCImoiET7IElqxN9htdDXQJwcRK+71r/ZyO4YJpWuX\n" +
                "0sAAAcEFc3nT+un31sOi8KoBJlc5n+MemntQvcWDs8B87BEW/Ncjrs0s4pJpZKBQ\n" +
                "/AWc4wLCI3ylfMQJB2pICqaOO3KP3WepgTIw5fuZm6YfriKQi7uZvVx1N+uaCIoa\n" +
                "K2IVVf/7O9KZJ9GbsGYdpBj9IdaIZiVS3Xi8rwgQl3haI/EeHC3nnCsWyj23Fjt3\n" +
                "LjbMqpHbSnp8U1cQ8rXavrREaKv69PFeJio6/hRg32TzJqn05dPALRxHMEkxxa4h\n" +
                "FpVU\n" +
                "=edS5\n" +
                "-----END PGP MESSAGE-----";
        pipeStringToStdin(ciphertext);
        int exitCode = executeCommand("decrypt");
        assertEquals(SOPGPException.MissingArg.EXIT_CODE, exitCode);
    }

    @Test
    public void testEncryptDecryptWithFreshRSAKey() throws IOException {
        // Generate key
        File passwordFile = writeFile("password", "sw0rdf1sh");
        File keyFile = pipeStdoutToFile("key.asc");
        assertSuccess(executeCommand("generate-key", "--profile=rfc4880", "--with-key-password", passwordFile.getAbsolutePath(), "Alice <alice@example.org>"));

        File certFile = pipeStdoutToFile("cert.asc");
        pipeFileToStdin(keyFile);
        assertSuccess(executeCommand("extract-cert"));

        // Write plaintext
        File plaintextFile = writeFile("msg.txt", "Hello, World!\n");

        // Encrypt
        File ciphertextFile = pipeStdoutToFile("msg.asc");
        pipeFileToStdin(plaintextFile);
        assertSuccess(executeCommand("encrypt", "--profile=rfc4880", certFile.getAbsolutePath()));

        ByteArrayOutputStream decrypted = pipeStdoutToStream();
        pipeFileToStdin(ciphertextFile);
        assertSuccess(executeCommand("decrypt", "--with-key-password", passwordFile.getAbsolutePath(), keyFile.getAbsolutePath()));

        assertEquals("Hello, World!\n", decrypted.toString());
    }
}
