/*
 * Copyright (c) 2023. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

package investigations;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MissingKeyPassphraseStrategy;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class PgpDecryptMultiThreadsTest {
    private static final String SENDER_PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "lIYEYIq7phYJKwYBBAHaRw8BAQdAat45rrh+gvQwWwJw5eScq3Pdxt/8d+lWNVSm\n" +
            "kImXcRP+CQMCvWfx3mzDdd5g6c59LcPqADK0p70/7ZmTkp3ZC1YViTprg4tQt/PF\n" +
            "QJL+VPCG+BF9bWyFcfxKe+KAnXRTWml5O6xrv6ZkiNmAxoYyO1shzLQWZGVmYXVs\n" +
            "dEBmbG93Y3J5cHQudGVzdIh4BBMWCgAgBQJgirumAhsDBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCHgECGQEACgkQIl+AI8INCVcysgD/cu23M07rImuV5gIl98uOnSIR+QnHUD/M\n" +
            "I34b7iY/iTQBALMIsqO1PwYl2qKwmXb5lSoMj5SmnzRRE2RwAFW3AiMCnIsEYIq7\n" +
            "phIKKwYBBAGXVQEFAQEHQA8q7iPr+0OXqBGBSAL6WNDjzHuBsG7uiu5w8l/A6v8l\n" +
            "AwEIB/4JAwK9Z/HebMN13mCOF6Wy/9oZK4d0DW9cNLuQDeRVZejxT8oFMm7G8iGw\n" +
            "CGNjIWWcQSvctBZtHwgcMeplCW7tmzkD3Nq/ty50lCwQQd6gZSXMiHUEGBYKAB0F\n" +
            "AmCKu6YCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRAiX4Ajwg0JV+sbAQCv4LVM\n" +
            "0+AN54ivWa4vPRyYOfSQ1FqsipkYLJce+xwUeAD+LZpEVCypFtGWQVdeSJVxIHx3\n" +
            "k40IfHsK0fGgR+NrRAw=\n" +
            "=osuI\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String SENDER_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "mDMEYIq7phYJKwYBBAHaRw8BAQdAat45rrh+gvQwWwJw5eScq3Pdxt/8d+lWNVSm\n" +
            "kImXcRO0FmRlZmF1bHRAZmxvd2NyeXB0LnRlc3SIeAQTFgoAIAUCYIq7pgIbAwUW\n" +
            "AgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJECJfgCPCDQlXMrIA/3LttzNO6yJrleYC\n" +
            "JffLjp0iEfkJx1A/zCN+G+4mP4k0AQCzCLKjtT8GJdqisJl2+ZUqDI+Upp80URNk\n" +
            "cABVtwIjArg4BGCKu6YSCisGAQQBl1UBBQEBB0APKu4j6/tDl6gRgUgC+ljQ48x7\n" +
            "gbBu7orucPJfwOr/JQMBCAeIdQQYFgoAHQUCYIq7pgIbDAUWAgMBAAQLCQgHBRUK\n" +
            "CQgLAh4BAAoJECJfgCPCDQlX6xsBAK/gtUzT4A3niK9Zri89HJg59JDUWqyKmRgs\n" +
            "lx77HBR4AP4tmkRULKkW0ZZBV15IlXEgfHeTjQh8ewrR8aBH42tEDA==\n" +
            "=kdDK\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String RECEIVER_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "mDMEYIucWBYJKwYBBAHaRw8BAQdAew+8mzMWyf3+Pfy49qa60uKV6e5os7de4TdZ\n" +
            "ceAWUq+0F2RlbmJvbmQ3QGZsb3djcnlwdC50ZXN0iHgEExYKACAFAmCLnFgCGwMF\n" +
            "FgIDAQAECwkIBwUVCgkICwIeAQIZAQAKCRDDIInNavjWzm3JAQCgFgCEyD58iEa/\n" +
            "Rw/DYNoQNoZC1lhw1bxBiOcIbtkdBgEAsDFZu3TBavOMKI7KW+vfMBHtRVbkMNpv\n" +
            "unaAldoabgO4OARgi5xYEgorBgEEAZdVAQUBAQdAB1/Mrq5JGYim4KqGTSK4OESQ\n" +
            "UwPgK56q0yrkiU9WgyYDAQgHiHUEGBYKAB0FAmCLnFgCGwwFFgIDAQAECwkIBwUV\n" +
            "CgkICwIeAQAKCRDDIInNavjWzjMgAQCU+R1fItqdY6lt9jXUqipmXuqVaEFPwNA8\n" +
            "YJ1rIwDwVQEAyUc8162KWzA2iQB5akwLwNr/pLDDtOWwhLUkrBb3mAc=\n" +
            "=pXF6\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String ENCRYPTED_TEXT = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4D16Pe22XLHvsSAQdAGnbsUSmPL/R4O24FqxHeD9oH5Fj6Ezut1mo8l0jU3S8w\n" +
            "9DDfnhxOcH8Zz+2PNVzkY/exM4iLQNkhio7f4iBV4krIZtMOEE4/2k+TdspAJzoI\n" +
            "hF4DTxRYvSK3u1MSAQdAPsETmZ27Dk9HFzLy/pd7ddXYqOkTJKk+fCcyfrhXXE4w\n" +
            "5aQ/hD9XtuuB7/KNLMOPcL+b6r6iiXw2Hh+pmhz6NTvgUYMjeKUitGaRXZcFBsro\n" +
            "0jsBimy6w2qk/a40HbcHRh/K+cZPqeN9rRAJU3pZoky0+wDNwpgFCB/GaCgZ69jV\n" +
            "p1k9Cdg9r5xsxpP3Tg==\n" +
            "=20Uz\n" +
            "-----END PGP MESSAGE-----";
    private static final String PASSPHRASE = "android";
    private static final String ORIGINAL_TEXT = "Some text";

    @Test
    public void testDecryptionInMultiThreads() throws PGPException, IOException {
        SecretKeyRingProtector secretKeyRingProtector =
                SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(PASSPHRASE));
        PGPPublicKeyRingCollection pgpPublicKeyRingCollection = PGPainless.readKeyRing().publicKeyRingCollection(
                SENDER_PUBLIC_KEY + "\n" + RECEIVER_PUBLIC_KEY);
        PGPSecretKeyRingCollection secretKeyRingCollection =
                PGPainless.readKeyRing().secretKeyRingCollection(SENDER_PRIVATE_KEY);


        try (DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ENCRYPTED_TEXT.getBytes()))
                .withOptions(
                        new ConsumerOptions()
                                .addDecryptionKeys(secretKeyRingCollection, secretKeyRingProtector)
                                .addVerificationCerts(pgpPublicKeyRingCollection)
                                .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.THROW_EXCEPTION)
                )) {
            ByteArrayOutputStream decrypted = new ByteArrayOutputStream();

            Streams.pipeAll(decryptionStream, decrypted);
            assertEquals(ORIGINAL_TEXT, decrypted.toString());
        }
    }
}
