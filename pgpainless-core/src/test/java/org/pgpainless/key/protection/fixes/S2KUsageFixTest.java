// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection.fixes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class S2KUsageFixTest {

    private static final String KEY_WITH_USAGE_CHECKSUM = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 23BF 0F50 8FE4 2304 6AC6  6EE3 7616 09ED DAF2 A7EE\n" +
            "Comment: Alice\n" +
            "\n" +
            "lHQEYTpM0xYJKwYBBAHaRw8BAQdA77HCCgjnEWBk9O9guvePTA7235v6yoTGUmUo\n" +
            "91V2OVr/CQMC5+tUnE2l4Ypg4dv9+qzBXjlQKAU5fktbQpIvYV9+pPXY6O+Wa7qJ\n" +
            "mIJsX2GsMR4uSLeAeQtFuPP0ZydL8rQFQWxpY2WIeAQTFgoAIAUCYTpM1AIbAQUW\n" +
            "AgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJEHYWCe3a8qfu9uYBAJGoTlRUEPCmzDBY\n" +
            "iqAXI8q1ZJDpYAF/AgdyfHgPZBLZAQDFagfWe/YyZV36EQ8P978gycUn4psQZyXE\n" +
            "QoNByDZDAJx5BGE6TNQSCisGAQQBl1UBBQEBB0BM9uoewIA3wDjChe7qdpp9B/uD\n" +
            "fQwxFj8AFcgR0qmDNgMBCAf/CQMC4B9NmOhlt+BgyZTk4BqqudczkJsRhoKPPC3e\n" +
            "TEqvyeBavp1fPgvAUfsZdL7Z8RoVQNd0LFptsj2zN2VcmIh1BBgWCgAdBQJhOkzU\n" +
            "AhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQdhYJ7dryp+4FxgEA29VePCidazQt\n" +
            "F6DfQCyNPW/d0Y+rm64KaMfBHJGCorQA/Rdg/gGVH7RoMiIJ8+kDxWOC92tn8JBJ\n" +
            "nIekiMcU45QJnHQEYTpM1BYJKwYBBAHaRw8BAQdAv2fItqEBrRsnrtWOU0Rc/S62\n" +
            "tafcr2huX3W5Nu6R1On/CQMCR9EMBma4cl9gE854C43bgYY2o53XSnBS/OMzo1rt\n" +
            "h+ixzZ6RZNafiAcXRUldVa55kc5KUvpc3y8lMlkDjYjVBBgWCgB9BQJhOkzUAhsC\n" +
            "BRYCAwEABAsJCAcFFQoJCAsCHgFfIAQZFgoABgUCYTpM1AAKCRB7qwD3I/Rg7Iic\n" +
            "AP4gOcJFEkRcNJMXVyXWWMaHGzvH7SJSn7/NDxjlbo+IhAD9HiPJoOm/88mHWxSr\n" +
            "udMemY82nrspaOyxcwqgkJbT8wIACgkQdhYJ7dryp+6yUQD+IufwT/XdopWA+GPD\n" +
            "IgT1CHRecJCkeYYmr7sZdPCLs3YA/jeVaFw4Z0drFnys4rh6aSoG6uf+YSba56V3\n" +
            "VBL8P8MC\n" +
            "=m6iF\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    // message encrypted to above key
    private static final String MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4DnMY7X1OYFewSAQdAxAxbWTZordzH+fN5s32ZU4PjYM/Og8z6DG7mrjOy+2Mw\n" +
            "BCiqa3G9GNZrRQyXihd1sFaxlgqiHrhhmFyCCMLgj2RxjZ7DJ4E0tA7RbF0lkqx4\n" +
            "0kAB1XXqAOJ50mEEQLYRN94xojDoJrlz2ZdmV1zqC2ZFd6YITEPIqSdwBuEG61rd\n" +
            "BLkPg8RuGdPMKZHZzOxIALtv\n" +
            "=//m8\n" +
            "-----END PGP MESSAGE-----";
    // same message, but unencrypted
    private static final String MESSAGE_PLAIN = "Hello, World!\n";

    @Test
    public void verifyOutFixInChangePassphraseWorks()
            throws PGPException {
        PGPSecretKeyRing before = PGPainless.generateKeyRing().modernKeyRing("Alice", "before");
        for (PGPSecretKey key : before) {
            assertEquals(SecretKeyPacket.USAGE_SHA1, key.getS2KUsage());
        }

        PGPSecretKeyRing unprotected = PGPainless.modifyKeyRing(before)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("before"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();
        for (PGPSecretKey key : unprotected) {
            assertEquals(SecretKeyPacket.USAGE_NONE, key.getS2KUsage());
        }

        PGPSecretKeyRing after = PGPainless.modifyKeyRing(unprotected)
                .changePassphraseFromOldPassphrase(Passphrase.emptyPassphrase())
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("after"))
                .done();
        for (PGPSecretKey key : after) {
            assertEquals(SecretKeyPacket.USAGE_SHA1, key.getS2KUsage());
        }
    }

    @Test
    public void testFixS2KUsageFrom_USAGE_CHECKSUM_to_USAGE_SHA1()
            throws IOException, PGPException {
        PGPSecretKeyRing keys = PGPainless.readKeyRing().secretKeyRing(KEY_WITH_USAGE_CHECKSUM);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("after"));

        PGPSecretKeyRing fixed = S2KUsageFix.replaceUsageChecksumWithUsageSha1(keys, protector);
        for (PGPSecretKey key : fixed) {
            assertEquals(SecretKeyPacket.USAGE_SHA1, key.getS2KUsage());
        }

        testCanStillDecrypt(keys, protector);
    }

    private void testCanStillDecrypt(PGPSecretKeyRing keys, SecretKeyRingProtector protector)
            throws PGPException, IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(keys, protector));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        assertArrayEquals(MESSAGE_PLAIN.getBytes(StandardCharsets.UTF_8), out.toByteArray());
    }
}
