// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;

public class RoundTripInlineSignInlineVerifyCmdTest extends CLITest {

    public RoundTripInlineSignInlineVerifyCmdTest() {
        super(LoggerFactory.getLogger(RoundTripInlineSignInlineVerifyCmdTest.class));
    }

    private static final String KEY_1_PASSWORD = "takeDemHobbits2Isengard";
    private static final String KEY_1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 59F4 EC7D 4A87 3E69 7029  8FDE 9FF0 8738 DFC0 0224\n" +
            "Comment: Legolas <legolas@fellowship.ring>\n" +
            "\n" +
            "lIYEY2wKdxYJKwYBBAHaRw8BAQdALfUbOSOsPDg4IgX7Mrub3EtkX0rp02orL/0j\n" +
            "2VpV1rf+CQMCVICwUO0SkvdgcPdvXO1cW4KIp6HCVVV6VgU5cvBlmrk9PNUQVBkb\n" +
            "6S7oXQu0CgGwJ+QdbooBQqOjMy2MDy+UXaURTaVyWcmetsZJZzD2wrQhTGVnb2xh\n" +
            "cyA8bGVnb2xhc0BmZWxsb3dzaGlwLnJpbmc+iI8EExYKAEEFAmNsCncJEJ/whzjf\n" +
            "wAIkFiEEWfTsfUqHPmlwKY/en/CHON/AAiQCngECmwEFFgIDAQAECwkIBwUVCgkI\n" +
            "CwKZAQAAE10BAN9tN4Le1p4giS6P/yFuKFlDBOeiq1S4EqwYG7qdcqemAP45O3w4\n" +
            "3sXliOJBGDR/l/lOMHdPcTOb7VRwWbpIqx8LBJyLBGNsCncSCisGAQQBl1UBBQEB\n" +
            "B0AMc+7s6uBqAQcDvfKkD5zYbmB9ZfwIjRWQq/XF+g8KQwMBCAf+CQMCVICwUO0S\n" +
            "kvdgHLmKhKW1xxCNZAqQcIHa9F/cqb6Sq/oVFHj2bEYzmGVvFCVUpP7KJWGTeFT+\n" +
            "BYK779quIqjxHOfzC3Jmo3BHkUPWYOa0rIh1BBgWCgAdBQJjbAp3Ap4BApsMBRYC\n" +
            "AwEABAsJCAcFFQoJCAsACgkQn/CHON/AAiRUewD9HtKrCUf3S1yR28emzITWPgJS\n" +
            "UA5mkzEMnYspV7zU4jgA/R6jj/5QqPszElCQNZGtvsDUwYo10iRlQkxPshcPNakJ\n" +
            "nIYEY2wKdxYJKwYBBAHaRw8BAQdAYxpRGib/f/tu65gbsV22nmysVVmVgiQuDxyH\n" +
            "rz7VCi/+CQMCVICwUO0SkvdgOYYbWltjQRDM3SW/Zw/DiZN9MYZYa0MTgs0SHoaM\n" +
            "5LU7jMxNmPR1UtSqEO36QqW91q4fpEkGrdWE4gwjm1bth8pyYKiSFojVBBgWCgB9\n" +
            "BQJjbAp3Ap4BApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUCY2wKdwAKCRCW\n" +
            "K491s9xIMHwKAQDpSWQqiFxFvls9eRGtJ1eQT+L3Z2rDel5zNV44IdTf/wEA0vnJ\n" +
            "ouSKKuiH6Ck2OEkXbElH6gdQvOCYA7Z9gVeeHQoACgkQn/CHON/AAiSD6QD+LTZx\n" +
            "NU+t4wQlWOkSsjOLsH/Sk5DZq+4HyQnStlxUJpUBALZFkZps65IP03VkPnQWigfs\n" +
            "YgztJA1z/rmm3fmFgMMG\n" +
            "=daDH\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String CERT_1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 59F4 EC7D 4A87 3E69 7029  8FDE 9FF0 8738 DFC0 0224\n" +
            "Comment: Legolas <legolas@fellowship.ring>\n" +
            "\n" +
            "mDMEY2wKdxYJKwYBBAHaRw8BAQdALfUbOSOsPDg4IgX7Mrub3EtkX0rp02orL/0j\n" +
            "2VpV1re0IUxlZ29sYXMgPGxlZ29sYXNAZmVsbG93c2hpcC5yaW5nPoiPBBMWCgBB\n" +
            "BQJjbAp3CRCf8Ic438ACJBYhBFn07H1Khz5pcCmP3p/whzjfwAIkAp4BApsBBRYC\n" +
            "AwEABAsJCAcFFQoJCAsCmQEAABNdAQDfbTeC3taeIIkuj/8hbihZQwTnoqtUuBKs\n" +
            "GBu6nXKnpgD+OTt8ON7F5YjiQRg0f5f5TjB3T3Ezm+1UcFm6SKsfCwS4OARjbAp3\n" +
            "EgorBgEEAZdVAQUBAQdADHPu7OrgagEHA73ypA+c2G5gfWX8CI0VkKv1xfoPCkMD\n" +
            "AQgHiHUEGBYKAB0FAmNsCncCngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRCf8Ic4\n" +
            "38ACJFR7AP0e0qsJR/dLXJHbx6bMhNY+AlJQDmaTMQydiylXvNTiOAD9HqOP/lCo\n" +
            "+zMSUJA1ka2+wNTBijXSJGVCTE+yFw81qQm4MwRjbAp3FgkrBgEEAdpHDwEBB0Bj\n" +
            "GlEaJv9/+27rmBuxXbaebKxVWZWCJC4PHIevPtUKL4jVBBgWCgB9BQJjbAp3Ap4B\n" +
            "ApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUCY2wKdwAKCRCWK491s9xIMHwK\n" +
            "AQDpSWQqiFxFvls9eRGtJ1eQT+L3Z2rDel5zNV44IdTf/wEA0vnJouSKKuiH6Ck2\n" +
            "OEkXbElH6gdQvOCYA7Z9gVeeHQoACgkQn/CHON/AAiSD6QD+LTZxNU+t4wQlWOkS\n" +
            "sjOLsH/Sk5DZq+4HyQnStlxUJpUBALZFkZps65IP03VkPnQWigfsYgztJA1z/rmm\n" +
            "3fmFgMMG\n" +
            "=/lYl\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String CERT_1_SIGNING_KEY =
            "D8906FEB9842569834FEDA9E962B8F75B3DC4830 59F4EC7D4A873E6970298FDE9FF08738DFC00224";

    private static final String KEY_2 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: AEA0 FD2C 899D 3FC0 7781  5F00 2656 0D2A E53D B86F\n" +
            "Comment: Gollum <gollum@deep.cave>\n" +
            "\n" +
            "lFgEY2wKphYJKwYBBAHaRw8BAQdA9MXACulaJvjIuMKbsc+/fLJ523lODbHmuTpc\n" +
            "jpPdjaEAAP9Edg7yeIGEeNP0GrndUpNeZyFAXAlCHJObDbS80G6BBw9ktBlHb2xs\n" +
            "dW0gPGdvbGx1bUBkZWVwLmNhdmU+iI8EExYKAEEFAmNsCqYJECZWDSrlPbhvFiEE\n" +
            "rqD9LImdP8B3gV8AJlYNKuU9uG8CngECmwEFFgIDAQAECwkIBwUVCgkICwKZAQAA\n" +
            "KSkBAOMq6ymNH83E5CBA/mn3DYLhnujzC9cVf/iX2zrsdXMvAQCWdfFy/PlGhP3K\n" +
            "M+ej6WIRsx24Yy/NhNPcRJUzcv6dC5xdBGNsCqYSCisGAQQBl1UBBQEBB0DiN/5n\n" +
            "AFQafWjnSkKhctFCNkfVRrnAea/2T/D8fYWeYwMBCAcAAP9HbxOhwxqz8I+pwk3e\n" +
            "kZXNolWqagrYZkpNvqlBb/JJWBGViHUEGBYKAB0FAmNsCqYCngECmwwFFgIDAQAE\n" +
            "CwkIBwUVCgkICwAKCRAmVg0q5T24bw2EAP4pUHVA2pkVspzEttIaQxdoHcnbwjae\n" +
            "q12TmWqWDFFvwgD+O2EqHn0iXW49EOQrlP8g+bdWUlT0ZIW3C3Fv7nNA3AScWARj\n" +
            "bAqmFgkrBgEEAdpHDwEBB0BHsmdF1Q0aU3YRVDeXGb904Nb7H/cxcasDhcbu2FTo\n" +
            "HAAA/j1+WzozN/3lefo76eyENKkXl4f1rQlUreqytuaTsb0WEq6I1QQYFgoAfQUC\n" +
            "Y2wKpgKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmNsCqYACgkQj73T\n" +
            "bQGDFnN9OwD/QDDi1qq7DrGlENQf2mPDh36YgM7bREY1vHEbbUNoqy4A/RJzMuwt\n" +
            "L1M49UzQS7OIGP12/9cT66XPGjpCL+6zLPwCAAoJECZWDSrlPbhvw3ABAOE7/Iit\n" +
            "ntMexrSK5jCd9JdCCNb2rjR6XA18rXFGOrVBAPwLKAogNFQlP2kUsObTnIaTCro2\n" +
            "cjK8WE1pfIwQ0ArPCQ==\n" +
            "=SzrG\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String CERT_2 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: AEA0 FD2C 899D 3FC0 7781  5F00 2656 0D2A E53D B86F\n" +
            "Comment: Gollum <gollum@deep.cave>\n" +
            "\n" +
            "mDMEY2wKphYJKwYBBAHaRw8BAQdA9MXACulaJvjIuMKbsc+/fLJ523lODbHmuTpc\n" +
            "jpPdjaG0GUdvbGx1bSA8Z29sbHVtQGRlZXAuY2F2ZT6IjwQTFgoAQQUCY2wKpgkQ\n" +
            "JlYNKuU9uG8WIQSuoP0siZ0/wHeBXwAmVg0q5T24bwKeAQKbAQUWAgMBAAQLCQgH\n" +
            "BRUKCQgLApkBAAApKQEA4yrrKY0fzcTkIED+afcNguGe6PML1xV/+JfbOux1cy8B\n" +
            "AJZ18XL8+UaE/coz56PpYhGzHbhjL82E09xElTNy/p0LuDgEY2wKphIKKwYBBAGX\n" +
            "VQEFAQEHQOI3/mcAVBp9aOdKQqFy0UI2R9VGucB5r/ZP8Px9hZ5jAwEIB4h1BBgW\n" +
            "CgAdBQJjbAqmAp4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQJlYNKuU9uG8NhAD+\n" +
            "KVB1QNqZFbKcxLbSGkMXaB3J28I2nqtdk5lqlgxRb8IA/jthKh59Il1uPRDkK5T/\n" +
            "IPm3VlJU9GSFtwtxb+5zQNwEuDMEY2wKphYJKwYBBAHaRw8BAQdAR7JnRdUNGlN2\n" +
            "EVQ3lxm/dODW+x/3MXGrA4XG7thU6ByI1QQYFgoAfQUCY2wKpgKeAQKbAgUWAgMB\n" +
            "AAQLCQgHBRUKCQgLXyAEGRYKAAYFAmNsCqYACgkQj73TbQGDFnN9OwD/QDDi1qq7\n" +
            "DrGlENQf2mPDh36YgM7bREY1vHEbbUNoqy4A/RJzMuwtL1M49UzQS7OIGP12/9cT\n" +
            "66XPGjpCL+6zLPwCAAoJECZWDSrlPbhvw3ABAOE7/IitntMexrSK5jCd9JdCCNb2\n" +
            "rjR6XA18rXFGOrVBAPwLKAogNFQlP2kUsObTnIaTCro2cjK8WE1pfIwQ0ArPCQ==\n" +
            "=j1LR\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String CERT_2_SIGNING_KEY =
            "7A073EDF273C902796D259528FBDD36D01831673 AEA0FD2C899D3FC077815F0026560D2AE53DB86F";

    private static final String MESSAGE = "One does not simply use OpenPGP!\n" +
            "\n" +
            "There is only one Lord of the Keys, only one who can bend them to his will. And he does not share power.";

    @Test
    public void createCleartextSignedMessage() throws IOException {
        File key = writeFile("key.asc", KEY_1);
        File password = writeFile("password", KEY_1_PASSWORD);

        pipeStringToStdin(MESSAGE);
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-sign",
                "--as", "clearsigned",
                key.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath()));

        String cleartextSigned = ciphertextOut.toString();
        assertTrue(cleartextSigned.startsWith("-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "Hash: "));
        assertTrue(cleartextSigned.contains(MESSAGE));
        assertTrue(cleartextSigned.contains("\n-----BEGIN PGP SIGNATURE-----\n"));
        assertTrue(cleartextSigned.endsWith("-----END PGP SIGNATURE-----\n"));
    }

    @Test
    public void createAndVerifyCleartextSignedMessage() throws IOException {
        File key = writeFile("key.asc", KEY_1);
        File password = writeFile("password", KEY_1_PASSWORD);

        pipeStringToStdin(MESSAGE);
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-sign",
                "--as", "clearsigned",
                key.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath()));

        File cert = writeFile("cert.asc", CERT_1);
        File verifications = nonExistentFile("verifications");
        pipeStringToStdin(ciphertextOut.toString());
        ByteArrayOutputStream plaintextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-verify",
                "--verifications-out", verifications.getAbsolutePath(),
                cert.getAbsolutePath()));

        assertEquals(MESSAGE, plaintextOut.toString());
        String verificationString = readStringFromFile(verifications);
        assertTrue(verificationString.contains(CERT_1_SIGNING_KEY));
    }

    @Test
    public void createAndVerifyTextSignedMessage() throws IOException {
        File key = writeFile("key.asc", KEY_1);
        File password = writeFile("password", KEY_1_PASSWORD);

        pipeStringToStdin(MESSAGE);
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-sign",
                "--as", "text",
                key.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath()));

        File cert = writeFile("cert.asc", CERT_1);
        File verifications = nonExistentFile("verifications");
        pipeStringToStdin(ciphertextOut.toString());
        ByteArrayOutputStream plaintextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-verify",
                "--verifications-out", verifications.getAbsolutePath(),
                cert.getAbsolutePath()));

        assertEquals(MESSAGE, plaintextOut.toString());
        String verificationString = readStringFromFile(verifications);
        assertTrue(verificationString.contains(CERT_1_SIGNING_KEY));
    }

    @Test
    public void createSignedMessageWithKeyAAndVerifyWithKeyBFails() throws IOException {
        File key = writeFile("key.asc", KEY_1);
        File password = writeFile("password", KEY_1_PASSWORD);
        File cert = writeFile("cert.asc", CERT_2); // mismatch

        pipeStringToStdin(MESSAGE);
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-sign",
                key.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath()));

        File verifications = nonExistentFile("verifications");
        pipeStringToStdin(ciphertextOut.toString());
        ByteArrayOutputStream plaintextOut = pipeStdoutToStream();
        int exitCode = executeCommand("inline-verify",
                "--verifications-out", verifications.getAbsolutePath(),
                cert.getAbsolutePath());

        assertEquals(SOPGPException.NoSignature.EXIT_CODE, exitCode);
        assertEquals(MESSAGE, plaintextOut.toString()); // message is emitted nonetheless
        assertFalse(verifications.exists(), "Verifications file MUST NOT be written.");
    }

    @Test
    public void createAndVerifyMultiKeyBinarySignedMessage() throws IOException {
        File key1Pass = writeFile("password", KEY_1_PASSWORD);
        File key1 = writeFile("key1.asc", KEY_1);
        File key2 = writeFile("key2.asc", KEY_2);

        pipeStringToStdin(MESSAGE);
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-sign",
                "--as", "binary",
                "--no-armor",
                key2.getAbsolutePath(),
                "--with-key-password", key1Pass.getAbsolutePath(),
                key1.getAbsolutePath()));

        assertFalse(ciphertextOut.toString().startsWith("-----BEGIN PGP SIGNED MESSAGE-----\n"));
        byte[] unarmoredMessage = ciphertextOut.toByteArray();

        File cert1 = writeFile("cert1.asc", CERT_1);
        File cert2 = writeFile("cert2.asc", CERT_2);
        File verificationFile = nonExistentFile("verifications");
        pipeBytesToStdin(unarmoredMessage);
        ByteArrayOutputStream plaintextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-verify",
                "--verifications-out", verificationFile.getAbsolutePath(),
                cert1.getAbsolutePath(), cert2.getAbsolutePath()));

        assertEquals(MESSAGE, plaintextOut.toString());
        String verification = readStringFromFile(verificationFile);
        assertTrue(verification.contains(CERT_1_SIGNING_KEY));
        assertTrue(verification.contains(CERT_2_SIGNING_KEY));
    }

    @Test
    public void createTextSignedMessageInlineDetachAndDetachedVerify() throws IOException {
        File key = writeFile("key.asc", KEY_1);
        File password = writeFile("password", KEY_1_PASSWORD);

        pipeStringToStdin(MESSAGE);
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-sign",
                "--as", "clearsigned",
                key.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath()));

        File sigFile = nonExistentFile("sig.asc");
        pipeStringToStdin(ciphertextOut.toString());
        ByteArrayOutputStream msgOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-detach",
                "--signatures-out", sigFile.getAbsolutePath()));
        assertEquals(MESSAGE, msgOut.toString());

        File cert = writeFile("cert.asc", CERT_1);
        pipeStringToStdin(msgOut.toString());
        ByteArrayOutputStream verificationsOut = pipeStdoutToStream();
        assertSuccess(executeCommand("verify",
                sigFile.getAbsolutePath(),
                cert.getAbsolutePath()));

        String verificationString = verificationsOut.toString();
        assertTrue(verificationString.contains(CERT_1_SIGNING_KEY));
    }

    @Test
    public void testUnlockKeyWithOneOfMultiplePasswords() throws IOException {
        File key = writeFile("key.asc", KEY_1);
        File wrong1 = writeFile("wrong_1", "BuzzAldr1n");
        File correct = writeFile("correct", KEY_1_PASSWORD);
        File wrong2 = writeFile("wrong_2", "NeilArmstr0ng");

        pipeStringToStdin(MESSAGE);
        ByteArrayOutputStream ciphertextOut = pipeStdoutToStream();
        assertSuccess(executeCommand("inline-sign",
                key.getAbsolutePath(),
                "--with-key-password", wrong1.getAbsolutePath(),
                "--with-key-password", correct.getAbsolutePath(),
                "--with-key-password", wrong2.getAbsolutePath()));

        File cert = writeFile("cert.asc", CERT_1);
        pipeStringToStdin(ciphertextOut.toString());
        ByteArrayOutputStream msgOut = pipeStdoutToStream();
        File verificationsFile = nonExistentFile("verifications");
        assertSuccess(executeCommand("inline-verify",
                "--verifications-out", verificationsFile.getAbsolutePath(),
                cert.getAbsolutePath()));

        assertEquals(MESSAGE, msgOut.toString());
        String verificationString = readStringFromFile(verificationsFile);
        assertTrue(verificationString.contains(CERT_1_SIGNING_KEY));
    }
}
