// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

/**
 * Test for #298.
 */
public class FixUserIdDoesNotBreakEncryptionCapabilityTest {

    private static final String SECRET_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lFgEYsyc4hYJKwYBBAHaRw8BAQdAjm3bQ61H2E6/xzjjHjl6G+mNl72r7fwdux9f\n" +
            "CXQrCpoAAQDwY5Vblm+7Dq8NfP5gqThyv+23aMBYLr3UgJAZyAgu/RDBtCQoQilv\n" +
            "YiAoSilvaG5zb24gPGJqQGV2YWx1YXRpb24udGVzdD6IkAQTFggAOBYhBI70BlHo\n" +
            "XvYV3ufIc8MDl+w8xmx4BQJizJziAhsjBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheA\n" +
            "AAoJEMMDl+w8xmx4ZAMBAIZsBqoClMlwymvNWIENCAZMQSy9NpBABk3jDyEjbhgs\n" +
            "AP9sGI7URQNUDXiV+sIzvastNX/nOZ7fkwp6Xrx+74WxC5xdBGLMnOISCisGAQQB\n" +
            "l1UBBQEBB0CGU2EGdS4mvy0apuPukStWSqEDH16AFSGEeTt2GyN1IQMBCAcAAP9J\n" +
            "nrIGndqzxxIUHVsoImYIu9SFl9Z1tCSia6mADTtbsA88iHgEGBYIACAWIQSO9AZR\n" +
            "6F72Fd7nyHPDA5fsPMZseAUCYsyc4gIbDAAKCRDDA5fsPMZseACnAQDIR7QwBTIs\n" +
            "Hfu4XIpZTyipOy6ZOEKlY3akyb9TtOq1wAD8Da+0Insssuf0J5WPqShJ/wMX3+xk\n" +
            "gqeRV2HyogQ7aAE=\n" +
            "=6zZo\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    private static final String CERTIFICATE = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mDMEYsyc4hYJKwYBBAHaRw8BAQdAjm3bQ61H2E6/xzjjHjl6G+mNl72r7fwdux9f\n" +
            "CXQrCpq0JChCKW9iIChKKW9obnNvbiA8YmpAZXZhbHVhdGlvbi50ZXN0PoiQBBMW\n" +
            "CAA4FiEEjvQGUehe9hXe58hzwwOX7DzGbHgFAmLMnOICGyMFCwkIBwIGFQoJCAsC\n" +
            "BBYCAwECHgECF4AACgkQwwOX7DzGbHhkAwEAhmwGqgKUyXDKa81YgQ0IBkxBLL02\n" +
            "kEAGTeMPISNuGCwA/2wYjtRFA1QNeJX6wjO9qy01f+c5nt+TCnpevH7vhbELuDgE\n" +
            "Ysyc4hIKKwYBBAGXVQEFAQEHQIZTYQZ1Lia/LRqm4+6RK1ZKoQMfXoAVIYR5O3Yb\n" +
            "I3UhAwEIB4h4BBgWCAAgFiEEjvQGUehe9hXe58hzwwOX7DzGbHgFAmLMnOICGwwA\n" +
            "CgkQwwOX7DzGbHgApwEAyEe0MAUyLB37uFyKWU8oqTsumThCpWN2pMm/U7TqtcAA\n" +
            "/A2vtCJ7LLLn9CeVj6koSf8DF9/sZIKnkVdh8qIEO2gB\n" +
            "=3sNT\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String userIdBefore = "(B)ob (J)ohnson <bj@evaluation.test>";
    private static final String userIdAfter = "\"(B)ob (J)ohnson\" <bj@evaluation.test>";

    @Test
    public void manualReplaceUserIdWithFixedVersionDoesNotHinderEncryptionCapability() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(SECRET_KEY);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPSecretKeyRing modified = PGPainless.modifyKeyRing(secretKeys)
                .addUserId(userIdAfter, new SelfSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setPrimaryUserId();
                    }
                }, protector)
                .removeUserId(userIdBefore, protector)
                .done();

        KeyRingInfo before = PGPainless.inspectKeyRing(secretKeys);
        KeyRingInfo after = PGPainless.inspectKeyRing(modified);

        assertEquals(userIdBefore, before.getPrimaryUserId());
        assertEquals(userIdAfter, after.getPrimaryUserId());
        assertTrue(after.isKeyValidlyBound(after.getKeyId()));
        assertTrue(before.isUsableForEncryption());
        assertTrue(before.isUsableForSigning());
        assertTrue(before.isUserIdValid(userIdBefore));
        assertFalse(before.isUserIdValid(userIdAfter));

        assertTrue(after.isUsableForEncryption());
        assertTrue(after.isUsableForSigning());
        assertFalse(after.isUserIdValid(userIdBefore));
        assertTrue(after.isUserIdValid(userIdAfter));
    }

    @Test
    public void testReplaceUserId_missingOldUserIdThrows() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(SECRET_KEY);
        assertThrows(NoSuchElementException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .replaceUserId("missing", userIdAfter, SecretKeyRingProtector.unprotectedKeys()));
    }

    @Test
    public void testReplaceUserId_emptyOldUserIdThrows() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(SECRET_KEY);
        assertThrows(IllegalArgumentException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .replaceUserId("     ", userIdAfter, SecretKeyRingProtector.unprotectedKeys()));
    }

    @Test
    public void testReplaceUserId_emptyNewUserIdThrows() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(SECRET_KEY);
        assertThrows(IllegalArgumentException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .replaceUserId(userIdBefore, "     ", SecretKeyRingProtector.unprotectedKeys()));
    }

    @Test
    public void testReplaceImplicitUserIdDoesNotBreakStuff() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(SECRET_KEY);

        PGPSecretKeyRing edited = PGPainless.modifyKeyRing(secretKeys)
                .replaceUserId(userIdBefore, userIdAfter, SecretKeyRingProtector.unprotectedKeys())
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(edited);
        assertTrue(info.isUserIdValid(userIdAfter));
        assertEquals(userIdAfter, info.getPrimaryUserId());

        PGPSignature latestCertification = info.getLatestUserIdCertification(userIdAfter);
        assertNotNull(latestCertification);
        assertTrue(latestCertification.getHashedSubPackets().isPrimaryUserID());

        PGPPublicKeyRing cert = PGPainless.extractCertificate(edited);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(new EncryptionOptions()
                        .addRecipient(cert)));

        encryptionStream.write("Hello".getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();

        EncryptionResult result = encryptionStream.getResult();
        assertTrue(result.isEncryptedFor(cert));

        ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
        ByteArrayOutputStream plain = new ByteArrayOutputStream();
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(edited));

        Streams.pipeAll(decryptionStream, plain);
        decryptionStream.close();

        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isEncrypted());
    }
}
