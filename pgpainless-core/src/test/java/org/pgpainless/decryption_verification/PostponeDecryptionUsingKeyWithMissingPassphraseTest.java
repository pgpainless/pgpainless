// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.CachingSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.s2k.Passphrase;

public class PostponeDecryptionUsingKeyWithMissingPassphraseTest {

    private static PGPSecretKeyRing k1;
    private static PGPSecretKeyRing k2;
    private static final Passphrase p1 = Passphrase.fromPassword("P1");
    private static final Passphrase p2 = Passphrase.fromPassword("P2");

    private static final String PLAINTEXT = "Hello, World!\n";

    // message is encrypted for both k1 and k2.
    // The first PKESK is for k1, the second for k2
    private static final String ENCRYPTED_FOR_K1_K2 = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4Dp8eMx2kPzEYSAQdAk0P2LL3pqZdq46eAGFkkESamDoPTn0EOLuPP+iA8lx8w\n" +
            "RAMb6mUxPDVGqoXt05h2ps4BOTpy+Utsli0+BUzXTvtGM6RDTkaCuZvHQwPsggnN\n" +
            "hF4DENqQkAsc7GgSAQdAJHwMR6+P5+HxwF8RqBEfrMCr0ZXWaLbekXf+FGTf/HYw\n" +
            "+Et5NgaJazx0BdCf+D11Q4Vvem4Z9UEFL7x89B4mnv1dkJWRNwH6CkCNYVyIVrHi\n" +
            "0kABB8V6DKCC1PNYlwCbSARz6X+xS9NsTFjGyROXajVEQ3x3ecLyKnyKxpcCJ2cb\n" +
            "lfnLZ5ezQoyoukRkcdul1CWf\n" +
            "=pvaA\n" +
            "-----END PGP MESSAGE-----";

    private static final String ENCRYPTED_FOR_K2_PASS_K1 = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4DENqQkAsc7GgSAQdAqtuQIjsRLypFfT8UykXqOv0dnrZWcrZBEiek4DNufmsw\n" +
            "zRgbpnyKme7LaM+Lu0yJk9wUsvdpypB5GrKY9cD1Hg5nx4bGyujC6olowa/8o6Xe\n" +
            "jC4ECQMCrjrXCpFawJtgj0y9PpciV6TpHJtI+lGbMed1+c5u3+U/HpRjLl3wBv9C\n" +
            "hF4Dp8eMx2kPzEYSAQdA+Qrv5R4hOnOuVHDJpCCW72ONcdnzEhw45MxT/7mp3nQw\n" +
            "8xs3dyVjMwmvqhbce9LIRdEM5YBWj3nBQM5ZQURAaQHPTTFuqCd8AgbeUz5FOFrA\n" +
            "0kABJpvij5utFmhTVDqm3TrWOAmZ/eba0GMg0g/vFh7HoEGr1gRHLpc+vaIMs+fF\n" +
            "uXVb1J9NX60PiBqxnM2iIBtD\n" +
            "=p8Ye\n" +
            "-----END PGP MESSAGE-----";
    private static final Passphrase PASSPHRASE = Passphrase.fromPassword("Wow!");

    @BeforeAll
    public static void prepareKeys() throws IOException {
        k1 = PGPainless.readKeyRing().secretKeyRing("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 9D0D 40DD 5B0A B5C7 9E73  E847 71BD 67EB 18A5 1034\n" +
                "Comment: K1\n" +
                "\n" +
                "lIYEYUH25xYJKwYBBAHaRw8BAQdAfnFMBZxpsZiJ0yheGIzWEQixVWexv3oxBpUS\n" +
                "kboJPIP+CQMCBjB6dP815OFgNjItEDhZVpGgZfHd9eqdNGj7RRiz7QN6Egk4kpGF\n" +
                "Mqd0wZ8Ey4vmiYaeSP7QT+Wf9EccHOR4D8XD+y//Pu5aJx1X7gmVvLQCSzGIeAQT\n" +
                "FgoAIAUCYUH25wIbAQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJEHG9Z+sYpRA0\n" +
                "OqkA/il0Tw+95YKXK5oPgqoHTzR5zaRyjmZ3r8Pjp5S+gCZYAP0RMmleSMVxkf+o\n" +
                "4FBKwE+Vv41GPYKBUQ2op/mCOyc3CpyLBGFB9ucSCisGAQQBl1UBBQEBB0C2DoDx\n" +
                "UjTXA/vFikJr64fB8qcCMyBx5ODBwBG9woSvLAMBCAf+CQMCBjB6dP815OFg8JuS\n" +
                "6Z6j+M+7X8QNhZtHohmGbbWntREzAAVlN+UEmLljpcKdZKqlPgGoacw2ta/928FR\n" +
                "6GD7tjyAPzSRTqPo6+pwBjU4/4h1BBgWCgAdBQJhQfbnAhsMBRYCAwEABAsJCAcF\n" +
                "FQoJCAsCHgEACgkQcb1n6xilEDReNgD+L+B9YfbIPGd4NnOvt+9qrrzmRPXbhTu7\n" +
                "9Vw0VmW7YfcBANH+0tH7HYbL5NOzGI888E28V0VhHqhhvtlctI574qAInIYEYUH2\n" +
                "5xYJKwYBBAHaRw8BAQdARWEfFJZIKcsMrb/A3/AwFgwTLqMmoK6XTuTUfuqxZCb+\n" +
                "CQMCBjB6dP815OFgHXyV5OYmG3BDr8xnw8boGZEdZRQARrbmYLCBEblH8X7X/jJy\n" +
                "/SdBnsKed/dVItHAENVBjkbFXx7V8z7jqmZAEDSFR7R6o4jVBBgWCgB9BQJhQfbn\n" +
                "AhsCBRYCAwEABAsJCAcFFQoJCAsCHgFfIAQZFgoABgUCYUH25wAKCRD9CYoy8Jjb\n" +
                "qYXCAP487XkaTSeqHiygM9x5jKJQzBTNoa8LP5kmhk/qiRMKWAEAnEOvrTRMS9OL\n" +
                "qLPQDJ5Zl4fwjXDC4MDEstxkwEkUXQEACgkQcb1n6xilEDTK+QD6AwFVz+NguD9k\n" +
                "MElK0o9VDLUWheP9tXE/sHcCVXKrm4kA/2TK8puF9FKpBb3pJhsvLfFuklVlXEBv\n" +
                "/lv8PRbqIHsN\n" +
                "=PETI\n" +
                "-----END PGP PRIVATE KEY BLOCK-----");
        k2 = PGPainless.readKeyRing().secretKeyRing("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 1458 6C84 3082 7226 5F4A  1EAC 15C9 772F 51A3 F48A\n" +
                "Comment: K2\n" +
                "\n" +
                "lIYEYUH25xYJKwYBBAHaRw8BAQdAQHpL7nSEOpOdEVcmNxTsjJmqPYI7ObVGZqCi\n" +
                "snlK8XP+CQMCySs/5txmbAtgB6fPvXfs7I0bYIEcGNZqSPMqVU04EjLyvmeP2EZL\n" +
                "L5ezq3U4Z835xEILFN5ngBxajMEu1A0pksiabHTR28RspoBDph+4/bQCSzKIeAQT\n" +
                "FgoAIAUCYUH25wIbAQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJEBXJdy9Ro/SK\n" +
                "vyQBALXaK7xt/JbIE4jqhWbliIHm8bskX3WG+jME5XjfDjBGAQC8hcKiWbOAF1tK\n" +
                "8KH2mzeHsh0yhybUvlq6wq7GZ3aZCZyLBGFB9ucSCisGAQQBl1UBBQEBB0CDCUwj\n" +
                "XBrIL5xf7TDKNOCyXgepXp+Ca3q2q0qmWm1nYwMBCAf+CQMCySs/5txmbAtg0/tL\n" +
                "Rw8WbfHVGS3u+aEuookij7swVMTspPY/s1W3Mt1TP85lM1Bkn5fDr4UP9prEQNc7\n" +
                "/fWsqvc1b9ZRBBqmwPOsKDfd3oh1BBgWCgAdBQJhQfbnAhsMBRYCAwEABAsJCAcF\n" +
                "FQoJCAsCHgEACgkQFcl3L1Gj9IoDBAD/YNTgbTvgM6UsqJ1DFiaihR1kV3nv2fuc\n" +
                "EAJfu7guvbsA/0gnPBxywJd4cK7spoAZjyjdgN8RPcZcUo6vXbMnT4YHnIYEYUH2\n" +
                "5xYJKwYBBAHaRw8BAQdApegYPw86Q19XMX1M5YykP51E27ZvwBIMc1bORa7xAFv+\n" +
                "CQMCySs/5txmbAtgFrYkIkpujELJEpD1hJlFSZzIxiA193PXfdo9CbFHBkjwIBh7\n" +
                "idT7l1gA+eHhiC0QyEPt3un3P4gj4UMeBPtCwqTUxo887IjVBBgWCgB9BQJhQfbn\n" +
                "AhsCBRYCAwEABAsJCAcFFQoJCAsCHgFfIAQZFgoABgUCYUH25wAKCRBQkr/WCypZ\n" +
                "Xp2zAP43zOQPtlbM1cabvP8kaWEsYG/x9ka4GtT/vkFh2cg3NAD/aSi13QhFHIVq\n" +
                "FI+3tH0vnxFAWmU9u7JnvM2+3ULHDA0ACgkQFcl3L1Gj9IqeqQEAx/2y5PMGl7t4\n" +
                "oHOJ4zhtqzTo33qjbu05eneS+zp4ElYA/RP/IGjIVz9wzraOKzBptB1BOaiqu3JG\n" +
                "xnMR9GND5bgA\n" +
                "=Sknt\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n");
    }

    @Test
    public void missingPassphraseFirst() throws PGPException, IOException {
        SecretKeyRingProtector protector1 = new CachingSecretKeyRingProtector(new SecretKeyPassphraseProvider() {
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                fail("Although the first PKESK is for k1, we should have skipped it and tried k2 first, which has passphrase available.");
                return null;
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return false;
            }
        });
        SecretKeyRingProtector protector2 = SecretKeyRingProtector.unlockEachKeyWith(p2, k2);

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ENCRYPTED_FOR_K1_K2.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(k1, protector1)
                        .addDecryptionKey(k2, protector2));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        assertEquals(PLAINTEXT, out.toString());
    }

    @Test
    public void missingPassphraseSecond() throws PGPException, IOException {
        SecretKeyRingProtector protector1 = SecretKeyRingProtector.unlockEachKeyWith(p1, k1);
        SecretKeyRingProtector protector2 = new CachingSecretKeyRingProtector(new SecretKeyPassphraseProvider() {
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                fail("This callback should not get called, since the first PKESK is for k1, which has a passphrase available.");
                return null;
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return false;
            }
        });

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ENCRYPTED_FOR_K1_K2.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(k1, protector1)
                        .addDecryptionKey(k2, protector2));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        assertEquals(PLAINTEXT, out.toString());
    }

    @Test
    public void messagePassphraseFirst() throws PGPException, IOException {
        SecretKeyPassphraseProvider provider = new SecretKeyPassphraseProvider() {
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                fail("Since we provide a decryption passphrase, we should not try to decrypt any key.");
                return null;
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return false;
            }
        };
        SecretKeyRingProtector protector = new CachingSecretKeyRingProtector(provider);

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ENCRYPTED_FOR_K2_PASS_K1.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addDecryptionPassphrase(PASSPHRASE)
                        .addDecryptionKey(k1, protector)
                        .addDecryptionKey(k2, protector));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        assertEquals(PLAINTEXT, out.toString());
    }
}
