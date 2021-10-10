// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sop.ByteArrayAndResult;
import sop.DecryptionResult;
import sop.SOP;
import sop.exception.SOPGPException;

public class EncryptDecryptRoundTripTest {

    private static SOP sop;
    private static byte[] aliceKey;
    private static byte[] aliceCert;
    private static byte[] bobKey;
    private static byte[] bobCert;
    private static byte[] message = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public static void setup() throws IOException {
        sop = new SOPImpl();
        aliceKey = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .generate()
                .getBytes();
        aliceCert = sop.extractCert()
                .key(aliceKey)
                .getBytes();
        bobKey = sop.generateKey()
                .userId("Bob <bob@pgpainless.org>")
                .generate()
                .getBytes();
        bobCert = sop.extractCert()
                .key(bobKey)
                .getBytes();
    }

    @Test
    public void basicRoundTripWithKey() throws IOException, SOPGPException.CertCannotSign {
        byte[] encrypted = sop.encrypt()
                .signWith(aliceKey)
                .withCert(aliceCert)
                .withCert(bobCert)
                .plaintext(message)
                .getBytes();

        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt()
                .withKey(bobKey)
                .verifyWithCert(aliceCert)
                .ciphertext(encrypted)
                .toByteArrayAndResult();

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        Streams.pipeAll(bytesAndResult.getInputStream(), decrypted);
        assertArrayEquals(message, decrypted.toByteArray());

        DecryptionResult result = bytesAndResult.getResult();
        assertEquals(1, result.getVerifications().size());
    }

    @Test
    public void basicRoundTripWithoutArmorUsingKey() throws IOException, SOPGPException.CertCannotSign {
        byte[] aliceKeyNoArmor = sop.generateKey()
                .userId("Alice <alice@unarmored.org>")
                .noArmor()
                .generate()
                .getBytes();
        byte[] aliceCertNoArmor = sop.extractCert()
                .noArmor()
                .key(aliceKeyNoArmor)
                .getBytes();
        byte[] encrypted = sop.encrypt()
                .signWith(aliceKeyNoArmor)
                .withCert(aliceCertNoArmor)
                .noArmor()
                .plaintext(message)
                .getBytes();

        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt()
                .withKey(aliceKeyNoArmor)
                .verifyWithCert(aliceCertNoArmor)
                .ciphertext(encrypted)
                .toByteArrayAndResult();

        byte[] decrypted = bytesAndResult.getBytes();
        assertArrayEquals(message, decrypted);

        DecryptionResult result = bytesAndResult.getResult();
        assertEquals(1, result.getVerifications().size());
    }

    @Test
    public void basicRoundTripWithPassword() throws IOException {
        byte[] encrypted = sop.encrypt()
                .withPassword("passphr4s3")
                .plaintext(message)
                .getBytes();

        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt()
                .withPassword("passphr4s3")
                .ciphertext(encrypted)
                .toByteArrayAndResult();

        byte[] decrypted = bytesAndResult.getBytes();
        assertArrayEquals(message, decrypted);

        DecryptionResult result = bytesAndResult.getResult();
        assertEquals(0, result.getVerifications().size());
    }

    @Test
    public void roundTripWithDecryptionPasswordContainingWhitespace() throws IOException {
        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt()
                .withPassword("passphr4s3    ") // whitespace is removed
                .ciphertext(
                        sop.encrypt()
                                .withPassword("passphr4s3")
                                .plaintext(message)
                                .getInputStream()
                )
                .toByteArrayAndResult();

        byte[] decrypted = bytesAndResult.getBytes();
        assertArrayEquals(message, decrypted);

        DecryptionResult result = bytesAndResult.getResult();
        assertEquals(0, result.getVerifications().size());
    }

    @Test
    public void roundTripWithEncryptionPasswordContainingWhitespace() throws IOException {
        byte[] encrypted = sop.encrypt()
                .withPassword("passphr4s3    ")
                .plaintext(message)
                .getBytes();

        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt()
                .withPassword("passphr4s3    ")
                .ciphertext(encrypted)
                .toByteArrayAndResult();

        byte[] decrypted = bytesAndResult.getBytes();
        assertArrayEquals(message, decrypted);

        DecryptionResult result = bytesAndResult.getResult();
        assertEquals(0, result.getVerifications().size());
    }

    @Test
    public void encrypt_decryptAndVerifyYieldsNoSignatureException() throws IOException {
        byte[] encrypted = sop.encrypt()
                .withCert(bobCert)
                .plaintext(message)
                .getBytes();

        assertThrows(SOPGPException.NoSignature.class, () -> sop
                .decrypt()
                .withKey(bobKey)
                .verifyWithCert(aliceCert)
                .ciphertext(encrypted)
                .toByteArrayAndResult());
    }

    @Test
    public void encrypt_decryptWithoutKeyOrPassphraseYieldsMissingArgException() throws IOException {
        byte[] encrypted = sop.encrypt()
                .withCert(bobCert)
                .plaintext(message)
                .getBytes();

        assertThrows(SOPGPException.MissingArg.class, () -> sop
                .decrypt()
                .ciphertext(encrypted)
                .toByteArrayAndResult());
    }

    @Test
    public void decrypt_withKeyWithMultipleKeysFails() {
        byte[] keys = new byte[aliceKey.length + bobKey.length];
        System.arraycopy(aliceKey, 0, keys, 0 , aliceKey.length);
        System.arraycopy(bobKey, 0, keys, aliceKey.length, bobKey.length);

        assertThrows(SOPGPException.BadData.class, () -> sop.decrypt()
                .withKey(keys));
    }

    @Test
    public void decrypt_withKeyWithPasswordProtectionFails() {
        String passwordProtectedKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 1777 B08F B9FE 25B8 E32C  E2E2 5974 2F3E DEC0 1772\n" +
                "Comment: Protected <protected@pgpainless.org>\n" +
                "\n" +
                "lIYEYSztkRYJKwYBBAHaRw8BAQdAMAcay1YOujgMVAXQsAz/QwL2PHc8EBroTQpe\n" +
                "Skizmyf+CQMC03aJCFqkseNgXBlZLknishdIO2iMz5YT2ptOjDkYLenEc71LqDTZ\n" +
                "abhG9vjfaMtfUvfF6qZurbvVAC0QBr/cSVREuEqDCxpbmYKeFrMz6LQkUHJvdGVj\n" +
                "dGVkIDxwcm90ZWN0ZWRAcGdwYWlubGVzcy5vcmc+iHgEExYKACAFAmEs7ZECGwEF\n" +
                "FgIDAQAECwkIBwUVCgkICwIeAQIZAQAKCRBZdC8+3sAXcksuAP961t8IhIHK7cG9\n" +
                "O7DjNNi35rEgvtHK6yC529gCzE5cBAEAjEgCHSu9UK4SQOSCiQNPKIJ4UUTuCWm8\n" +
                "bla6dtuB1QSciwRhLO2REgorBgEEAZdVAQUBAQdAqVXssfkOprxE8weHZoa7T/5f\n" +
                "kbGOA/6hmzLoYfWURhEDAQgH/gkDAtN2iQhapLHjYEJJ+kwyW2SnEFhMoWKZBG94\n" +
                "RV+S+rwq+ITz/CV53Qc/XcveX6x4QmoXqK6ges7dDLYog/iJ/tFAMeV//LJHpow/\n" +
                "U2SA6XGIdQQYFgoAHQUCYSztkQIbDAUWAgMBAAQLCQgHBRUKCQgLAh4BAAoJEFl0\n" +
                "Lz7ewBdyWJkA/j8zj+6AhhAJOdlfqA2empI+eZfZQg8D1uB/QfKNh+5CAP9VYUUf\n" +
                "EZMNtnSCXP6ERFy1/CJLW4eqLL19oVBJ/mvMDJyGBGEs7ZEWCSsGAQQB2kcPAQEH\n" +
                "QMZgsx/zrhfULWNsjs0ZREzEwLsPRzSgh9zKn53U/zlY/gkDAtN2iQhapLHjYHe7\n" +
                "hmEPgxR7lsOZJazPnBzJGP6uRs4ts6m7e4MfEF2gk0N+iaQPowkypZS98pN5rsDg\n" +
                "t9Yby6+IgqSQkMZitZAxnfepOCOI1QQYFgoAfQUCYSztkQIbAgUWAgMBAAQLCQgH\n" +
                "BRUKCQgLAh4BXyAEGRYKAAYFAmEs7ZEACgkQpHV13KorLUkL3gEAnNx1GARit/FL\n" +
                "4OoL0dINsmTCF8hQKe2OGgNhhkN8v90A/i2RifktEqcmMW1ezSRGlmn5hx5bTWRc\n" +
                "99Ts4FiwRLQJAAoJEFl0Lz7ewBdyaysA/jk61StphMpfuRsuQwznH7L7SddNcZ1k\n" +
                "l1wHK5kRJXyCAP0WUgkpEcM2bpwb4sxkCDxrfk/ixc47hGa68MPWwOJkAQ==\n" +
                "=MUYS\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";

        assertThrows(SOPGPException.KeyIsProtected.class, () -> sop.decrypt()
                .withKey(passwordProtectedKey.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void verifyWith_noDataThrowsBadData() {
        assertThrows(SOPGPException.BadData.class, () -> sop.decrypt()
                .verifyWithCert(new byte[0]));
    }
}
