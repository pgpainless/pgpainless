// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sop.ByteArrayAndResult;
import sop.DecryptionResult;
import sop.SOP;
import sop.SessionKey;
import sop.enums.SignatureMode;
import sop.exception.SOPGPException;
import sop.testsuite.assertions.VerificationListAssert;

public class EncryptDecryptRoundTripTest {

    private static final Charset utf8 = Charset.forName("UTF8");
    private static SOP sop;
    private static byte[] aliceKey;
    private static final String alicePassword = "wonderland.is.c00l";
    private static byte[] aliceCert;
    private static byte[] bobKey;
    private static byte[] bobCert;
    private static byte[] message = "Hello, World!\n".getBytes(utf8);

    @BeforeAll
    public static void setup() throws IOException {
        sop = new SOPImpl();
        aliceKey = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .withKeyPassword(alicePassword)
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
    public void basicRoundTripWithKey() throws IOException, SOPGPException.KeyCannotSign {
        byte[] encrypted = sop.encrypt()
                .signWith(aliceKey)
                .withKeyPassword(alicePassword)
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
        VerificationListAssert.assertThatVerificationList(result.getVerifications())
                .hasSingleItem();
    }

    @Test
    public void basicRoundTripWithoutArmorUsingKey() throws IOException, SOPGPException.KeyCannotSign {
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
        VerificationListAssert.assertThatVerificationList(result.getVerifications())
                .hasSingleItem();
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
        VerificationListAssert.assertThatVerificationList(result.getVerifications())
                .isEmpty();
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
        VerificationListAssert.assertThatVerificationList(result.getVerifications())
                .isEmpty();
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
        VerificationListAssert.assertThatVerificationList(result.getVerifications())
                .isEmpty();
    }

    @Test
    public void encrypt_decryptAndVerifyYieldsNoVerifications() throws IOException {
        byte[] encrypted = sop.encrypt()
                .withCert(bobCert)
                .plaintext(message)
                .getBytes();

        DecryptionResult result = sop.decrypt()
                .withKey(bobKey)
                .verifyWithCert(aliceCert)
                .ciphertext(encrypted)
                .toByteArrayAndResult()
                .getResult();

        VerificationListAssert.assertThatVerificationList(result.getVerifications())
                .isEmpty();
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

        String msg = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4Doj0CaB2GRvISAQdAhV5sjUCxanM68jG9qaq2rep1KKQx2o+9yrK0Rsrtqkww\n" +
                "mb4uVv/SD3ixDztUSgUset0jeUeZHZAWfTB9cWawX4fiB2BdbcxhxFqQR8VPJ2SZ\n" +
                "0jcB+wH1gq05AkMaCfoEIio3o3QcZq2In8tqj69U3AFRQApoH/p+ZLDz2pcnFBn+\n" +
                "x1Y+C6wNg/3g\n" +
                "=6vge\n" +
                "-----END PGP MESSAGE-----";

        assertThrows(SOPGPException.KeyIsProtected.class, () -> sop.decrypt()
                .withKey(passwordProtectedKey.getBytes(StandardCharsets.UTF_8))
                .ciphertext(msg.getBytes(utf8)));
    }

    @Test
    public void encryptDecryptRoundTripWithProtectedKey() throws IOException {
        byte[] passphrase = "sw0rdf1sh".getBytes(utf8);

        byte[] key = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .withKeyPassword(passphrase)
                .generate().getBytes();

        byte[] cert = sop.extractCert()
                .key(key)
                .getBytes();

        byte[] plaintext = "Hello, World!\n".getBytes(utf8);

        byte[] ciphertext = sop.encrypt()
                .withCert(cert)
                .plaintext(plaintext)
                .getBytes();

        byte[] decrypted = sop.decrypt()
                .withKeyPassword(passphrase)
                .withKey(key)
                .ciphertext(ciphertext)
                .toByteArrayAndResult()
                .getBytes();

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void encryptDecryptRoundTripWithTwoProtectedKeysAndOnePassphrase() throws IOException {
        byte[] passphrase1 = "sw0rdf1sh".getBytes(utf8);

        byte[] key1 = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .withKeyPassword(passphrase1)
                .generate().getBytes();

        byte[] cert1 = sop.extractCert()
                .key(key1)
                .getBytes();

        byte[] passphrase2 = "fooBar".getBytes(utf8);

        byte[] key2 = sop.generateKey()
                .userId("Bob <bob@pgpainless.org>")
                .withKeyPassword(passphrase2)
                .generate().getBytes();

        byte[] cert2 = sop.extractCert()
                .key(key2)
                .getBytes();

        byte[] plaintext = "Hello, World!\n".getBytes(utf8);

        byte[] ciphertext = sop.encrypt()
                .withCert(cert1)
                .withCert(cert2)
                .plaintext(plaintext)
                .getBytes();

        byte[] decrypted = sop.decrypt()
                .withKey(key1)
                .withKey(key2)
                .withKeyPassword(passphrase2)
                .ciphertext(ciphertext)
                .toByteArrayAndResult()
                .getBytes();

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void encryptDecryptRoundTripFailsWithProtectedKeyAndWrongPassphrase() throws IOException {
        byte[] passphrase = "sw0rdf1sh".getBytes(utf8);

        byte[] key = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .withKeyPassword(passphrase)
                .generate().getBytes();

        byte[] cert = sop.extractCert()
                .key(key)
                .getBytes();

        byte[] plaintext = "Hello, World!\n".getBytes(utf8);

        byte[] ciphertext = sop.encrypt()
                .withCert(cert)
                .plaintext(plaintext)
                .getBytes();

        assertThrows(SOPGPException.KeyIsProtected.class,
                () -> sop.decrypt()
                        .withKeyPassword("foobar")
                        .withKey(key)
                        .ciphertext(ciphertext));
    }

    @Test
    public void verifyWith_noDataThrowsBadData() {
        assertThrows(SOPGPException.BadData.class, () -> sop.decrypt()
                .verifyWithCert(new byte[0]));
    }

    @Test
    public void testPassphraseDecryptionYieldsSessionKey() throws IOException {
        byte[] message = "Hello\nWorld\n".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = ("-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "jA0ECQMCdFswArqHpj1g0j4BLDTkZhCC1crZf0EFq1xPIMUtnyRmfJJ7IzsdMJ5Y\n" +
                "EhKbBc2h6wIX7B/GxUbyNj1xh5JRzt2ZX8KL2d6HAQ==\n" +
                "=zZ0/\n" +
                "-----END PGP MESSAGE-----").getBytes(StandardCharsets.UTF_8);
        String passphrase = "sw0rdf1sh";
        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt().withPassword(passphrase).ciphertext(ciphertext).toByteArrayAndResult();
        assertArrayEquals(message, bytesAndResult.getBytes());
        assertTrue(bytesAndResult.getResult().getSessionKey().isPresent());
        assertEquals("9:7BCB7383D23E20D4BA8980B26D6C0813769056546C45B7E55F4612BFAD5B4B1C", bytesAndResult.getResult().getSessionKey().get().toString());
    }

    @Test
    public void testPublicKeyDecryptionYieldsSessionKey() throws IOException {
        byte[] key = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: D94A AA9C 5F73 48B2 5D81  72E7 F20C F71E 93FE 897F\n" +
                "Comment: Alice\n" +
                "\n" +
                "lFgEYWlyaRYJKwYBBAHaRw8BAQdAJsJfjByLE+8HNVGbEKiIbSGXBYwR6L61bT5E\n" +
                "Hhu642kAAP49D4TOaI+Z3G5ko4C4D1bOzLajLRpIuPLuwYHpF1xD0RHmtAVBbGlj\n" +
                "ZYh4BBMWCgAgBQJhaXJpAhsBBRYCAwEABRUKCQgLBAsJCAcCHgECGQEACgkQ8gz3\n" +
                "HpP+iX/c8AD9Hx0PUu97n8ZlrpuA6YuJL3rONPQnaXMz9eE+KHxJS6sBAM06X8Wm\n" +
                "XRGUVURsoerwYTbUnXcUnqH/U/JhwlUerJAInF0EYWlyaRIKKwYBBAGXVQEFAQEH\n" +
                "QJOHyxI5K8ZqX+v/AmTLHAIjWd8wHO8eGld4KHniCFx9AwEIBwAA/0zVZYYWsr3w\n" +
                "GKkmqfIZlB+wIeJlWrho87kvXiNAe0LIEIGIdQQYFgoAHQUCYWlyaQIbDAUWAgMB\n" +
                "AAUVCgkICwQLCQgHAh4BAAoJEPIM9x6T/ol/vggA/ilxi5UTjDYDR7sGrYyaGPRK\n" +
                "Sg0KNn2SV4c5M5ZmZR7sAP4kKz6kQ4UtYmSmUmMBu+A3mMTN8VQY+6LSTdekvU0N\n" +
                "ApxYBGFpcmkWCSsGAQQB2kcPAQEHQJiiZENQ52jyt8wBwX7fD1vQkvgTg5T3v1S1\n" +
                "yzr1yI0RAAD+KOTcMdv8rz3U6K42PNE4b983KoMfyQ/hgjIWOi2BYBwP94jVBBgW\n" +
                "CgB9BQJhaXJpAhsCBRYCAwEABRUKCQgLBAsJCAcCHgFfIAQZFgoABgUCYWlyaQAK\n" +
                "CRDP7lemqmadIYLuAP9oAm+OFzyMNrmWRcvdHqH/DAfJTM2+ZmANSm44geZDEAD9\n" +
                "HfeCHev1H1H1wOd0S3tW9gZwonrYFoqOBW/YTmf5XwYACgkQ8gz3HpP+iX+veQEA\n" +
                "sWC+xDo+lc6oJr4q0mTJkxzYfgUBtQ0VjUWNcGyOdegBAL8hMzb9+e4wbP2F0tMb\n" +
                "ZFA2MgHsvqGhXyAXi50arZYF\n" +
                "=k66N\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n").getBytes(StandardCharsets.UTF_8);
        byte[] message = "Hello\nWorld\n".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = ("-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4DrJ3c2YF1IKUSAQdA9VL6OwIwOwB4GnE4yR5JJ5OjcC76WTpdm85I6WHvhD4w\n" +
                "hqHpf6UGaDDQ7xAcSd7YnEGVMBOOBnJfD1PRuNWE5hwgqqsqpMDrvvMHjUsg3HNH\n" +
                "0j4BriMU8XQ6MLdvCaFmeQqFwBD4mlI/x32wj0I9VyBIKysopA8HNV4ES2rOhGuW\n" +
                "T/zFmI9Tm9eWvNwv0LUNhQ==\n" +
                "=4Z+m\n" +
                "-----END PGP MESSAGE-----\n").getBytes(StandardCharsets.UTF_8);

        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt().withKey(key).ciphertext(ciphertext).toByteArrayAndResult();
        DecryptionResult result = bytesAndResult.getResult();
        assertArrayEquals(message, bytesAndResult.getBytes());
        assertTrue(result.getSessionKey().isPresent());
        assertEquals("9:63F741E7FB60247BE59C64158573308F727236482DB7653908C95839E4166AAE", result.getSessionKey().get().toString());
    }

    @Test
    public void testDecryptionWithSessionKey() throws IOException {
        byte[] message = "Hello\nWorld\n".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = ("-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4DrJ3c2YF1IKUSAQdA9VL6OwIwOwB4GnE4yR5JJ5OjcC76WTpdm85I6WHvhD4w\n" +
                "hqHpf6UGaDDQ7xAcSd7YnEGVMBOOBnJfD1PRuNWE5hwgqqsqpMDrvvMHjUsg3HNH\n" +
                "0j4BriMU8XQ6MLdvCaFmeQqFwBD4mlI/x32wj0I9VyBIKysopA8HNV4ES2rOhGuW\n" +
                "T/zFmI9Tm9eWvNwv0LUNhQ==\n" +
                "=4Z+m\n" +
                "-----END PGP MESSAGE-----\n").getBytes(StandardCharsets.UTF_8);
        SessionKey sessionKey = SessionKey.fromString("9:63F741E7FB60247BE59C64158573308F727236482DB7653908C95839E4166AAE");

        ByteArrayAndResult<DecryptionResult> bytesAndResult = sop.decrypt().withSessionKey(sessionKey)
                .ciphertext(ciphertext)
                .toByteArrayAndResult();

        DecryptionResult result = bytesAndResult.getResult();
        assertTrue(result.getSessionKey().isPresent());
        assertEquals(sessionKey, result.getSessionKey().get());

        assertArrayEquals(message, bytesAndResult.getBytes());
    }

    @Test
    public void testEncryptWithWrongPassphraseThrowsKeyIsProtected() {
        assertThrows(SOPGPException.KeyIsProtected.class, () -> sop.encrypt()
                .withKeyPassword("falsePassphrase")
                .signWith(aliceKey)
                .withCert(bobCert)
                .plaintext(message));
    }

    @Test
    public void testDecryptionWithSessionKey_VerificationWithCert() throws IOException {
        byte[] plaintext = "This is a test message.\nSit back and relax.\n".getBytes(StandardCharsets.UTF_8);
        byte[] key = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 9C26 EFAB 1C65 00A2 28E8  A9C2 658E E420 C824 D191\n" +
                "Comment: Alice\n" +
                "\n" +
                "lFgEYWl4ixYJKwYBBAHaRw8BAQdAv6+cd8R/ICS/z9hlT99g++wyquxVsO0FCb8F\n" +
                "MSkTplUAAP9gPoBi8fxdfLaEyt6GWeIBTeYsVxsogbKzXXnjp3MbiRE/tAVBbGlj\n" +
                "ZYh4BBMWCgAgBQJhaXiLAhsBBRYCAwEABRUKCQgLBAsJCAcCHgECGQEACgkQZY7k\n" +
                "IMgk0ZEZuAEA3hWzfqCXGUjlv+miWey1AyWRu9eQvTdE9YqbIMuxIk4BAMtGlo6l\n" +
                "d3E868q0zLOOktmsBxnzaE7knbd9nAlK3FUJnF0EYWl4ixIKKwYBBAGXVQEFAQEH\n" +
                "QK8vS3T3Yf3Gpy9iWOTR0jdhV4XgtchcvKCpFMgc5uwFAwEIBwAA/1tNle5cT9kS\n" +
                "8yzNxL16ElEREtEX+5kpkt6JZyTx0xfAEPGIdQQYFgoAHQUCYWl4iwIbDAUWAgMB\n" +
                "AAUVCgkICwQLCQgHAh4BAAoJEGWO5CDIJNGRM80BANJ6EGKIkVNxYj7wOaEqyRh1\n" +
                "Rtv3tLAnEzLl/b0mZx3WAQDADAPNCl5xnjTt5InyfrwV90kM4vDGcl4mQE8FD7dD\n" +
                "B5xYBGFpeIsWCSsGAQQB2kcPAQEHQFuEaBKUllw+MfdkkSNE0CncJCeFGCbHvmsc\n" +
                "Ma/DPgrpAAEAlsoxcTyTFfHxV2CayDCFvBSHYXOSOg6fyMdh0SxzjC0PVIjVBBgW\n" +
                "CgB9BQJhaXiLAhsCBRYCAwEABRUKCQgLBAsJCAcCHgFfIAQZFgoABgUCYWl4iwAK\n" +
                "CRBGMq3j1oKUXenjAP974AvBOAVIdNUkVAishoDL7ee7/eAU3Ni7V2Kn47cusQD/\n" +
                "c8c9phtf2NIL23K4bvBdvsU3opV2DIVJwRutV4v6jgAACgkQZY7kIMgk0ZG1dwEA\n" +
                "sFp1AuPcn3dGF05D6ohlqunoBwBWEcwZLjx+v5X27R8A/17V5nzC+eny3XjCF8Ib\n" +
                "qw1VTfR84stki65Xhm2lxFAN\n" +
                "=TQO7\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n").getBytes(StandardCharsets.UTF_8);
        byte[] cert = sop.extractCert().key(key).getBytes();
        byte[] ciphertext = ("-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4DSjXDMRql2RASAQdAkhJyA9GX5ios8PNlti7v7BieggiiR9trqrKFQwomU2Aw\n" +
                "elEFuDA3ugJO2rNiyQQH1riFFJuod6BiQuxFhdf/mmsFFDzHmJeUOx9pQeNemzST\n" +
                "0sAdAQQYC+iXUNn2y15kTqbFQFgfOWObgsqspGY04V17fZdVI7bEORLM+YT6KoZA\n" +
                "uq2WO49ze9jp2jdvTsjjNNseZDhmxtgOCfi1/Fi3IHPnBJW7M3UWaJCSLozWkO95\n" +
                "FztCSWL22jDGPGIjgQ589hYW+WuJMvMv6ltTOo+l70S5dHSObijbcOqfNSmrxlpw\n" +
                "hqZfkU0BA01I9Pf3lBPCNyMbCPZP0oaIiWACnm6svWp4oH5u5ClhS9BVJTptzwXv\n" +
                "mMj+lTi5ahGQJ3Nr8krloTSsjpkssz6D2+FDnvjwu6E=\n" +
                "=BYOB\n" +
                "-----END PGP MESSAGE-----").getBytes(StandardCharsets.UTF_8);
        String sessionKey = "9:87C0870598AD908ABEECCAE265DCEEA146CF557AAF698D097024404A00EBD072";

        // Decrypt with public key
        ByteArrayAndResult<DecryptionResult> bytesAndResult =
                sop.decrypt().withKey(key).verifyWithCert(cert).ciphertext(ciphertext).toByteArrayAndResult();
        assertEquals(sessionKey, bytesAndResult.getResult().getSessionKey().get().toString());
        assertArrayEquals(plaintext, bytesAndResult.getBytes());
        VerificationListAssert.assertThatVerificationList(bytesAndResult.getResult().getVerifications())
                .hasSingleItem()
                .issuedBy("9C26EFAB1C6500A228E8A9C2658EE420C824D191")
                .hasMode(SignatureMode.binary);
        // Decrypt with session key
        bytesAndResult = sop.decrypt().withSessionKey(SessionKey.fromString(sessionKey))
                .verifyWithCert(cert).ciphertext(ciphertext).toByteArrayAndResult();
        assertEquals(sessionKey, bytesAndResult.getResult().getSessionKey().get().toString());
        assertArrayEquals(plaintext, bytesAndResult.getBytes());
        VerificationListAssert.assertThatVerificationList(bytesAndResult.getResult().getVerifications())
                .hasSingleItem()
                .issuedBy("9C26EFAB1C6500A228E8A9C2658EE420C824D191")
                .hasMode(SignatureMode.binary);
    }

    @Test
    public void decryptWithWrongSessionKey() {
        byte[] ciphertext = ("-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "hF4DSjXDMRql2RASAQdAkhJyA9GX5ios8PNlti7v7BieggiiR9trqrKFQwomU2Aw\n" +
                "elEFuDA3ugJO2rNiyQQH1riFFJuod6BiQuxFhdf/mmsFFDzHmJeUOx9pQeNemzST\n" +
                "0sAdAQQYC+iXUNn2y15kTqbFQFgfOWObgsqspGY04V17fZdVI7bEORLM+YT6KoZA\n" +
                "uq2WO49ze9jp2jdvTsjjNNseZDhmxtgOCfi1/Fi3IHPnBJW7M3UWaJCSLozWkO95\n" +
                "FztCSWL22jDGPGIjgQ589hYW+WuJMvMv6ltTOo+l70S5dHSObijbcOqfNSmrxlpw\n" +
                "hqZfkU0BA01I9Pf3lBPCNyMbCPZP0oaIiWACnm6svWp4oH5u5ClhS9BVJTptzwXv\n" +
                "mMj+lTi5ahGQJ3Nr8krloTSsjpkssz6D2+FDnvjwu6E=\n" +
                "=BYOB\n" +
                "-----END PGP MESSAGE-----").getBytes(StandardCharsets.UTF_8);
        SessionKey wrongSessionKey = SessionKey.fromString("9:63F741E7FB60247BE59C64158573308F727236482DB7653908C95839E4166AAE");

        assertThrows(SOPGPException.CannotDecrypt.class, () ->
                sop.decrypt().withSessionKey(wrongSessionKey).ciphertext(ciphertext));
    }

    @Test
    public void decryptNonEncryptedDataFailsBadData() throws IOException {
        byte[] signed = sop.inlineSign()
                .key(aliceKey)
                .withKeyPassword(alicePassword)
                .data(message)
                .getBytes();

        assertThrows(SOPGPException.BadData.class, () ->
                sop.decrypt()
                        .verifyWithCert(aliceCert)
                        .withKey(aliceKey)
                        .withKeyPassword(alicePassword)
                        .ciphertext(signed)
                        .toByteArrayAndResult()
        );
    }
}
