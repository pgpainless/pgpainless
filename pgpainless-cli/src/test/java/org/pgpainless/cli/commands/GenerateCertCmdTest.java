// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.pgpainless.cli.TestUtils.ARMOR_PRIVATE_KEY_HEADER_BYTES;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.ginsberg.junit.exit.FailOnSystemExit;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.cli.PGPainlessCLI;
import org.pgpainless.cli.TestUtils;
import org.pgpainless.key.info.KeyInfo;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.s2k.Passphrase;

public class GenerateCertCmdTest {

    @Test
    @FailOnSystemExit
    public void testKeyGeneration() throws IOException, PGPException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("generate-key", "--armor", "Juliet Capulet <juliet@capulet.lit>");

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(out.toByteArray());
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isFullyDecrypted());
        assertTrue(info.isUserIdValid("Juliet Capulet <juliet@capulet.lit>"));

        for (PGPSecretKey key : secretKeys) {
            assertTrue(testPassphrase(key, null));
        }

        byte[] outBegin = new byte[37];
        System.arraycopy(out.toByteArray(), 0, outBegin, 0, 37);
        assertArrayEquals(outBegin, ARMOR_PRIVATE_KEY_HEADER_BYTES);
    }

    @Test
    @FailOnSystemExit
    public void testGenerateKeyWithPassword() throws IOException, PGPException {
        PrintStream orig = System.out;
        try {
            // Write password to file
            File tempDir = TestUtils.createTempDirectory();
            File passwordFile = TestUtils.writeTempFile(tempDir, "sw0rdf1sh".getBytes(StandardCharsets.UTF_8));

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            System.setOut(new PrintStream(out));
            PGPainlessCLI.execute("generate-key", "Juliet Capulet <juliet@capulet.lit>",
                    "--with-key-password", passwordFile.getAbsolutePath());

            PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(out.toByteArray());
            KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
            assertFalse(info.isFullyDecrypted());
            assertTrue(info.isFullyEncrypted());

            for (PGPSecretKey key : secretKeys) {
                assertTrue(testPassphrase(key, "sw0rdf1sh"));
            }
        } finally {
            System.setOut(orig);
        }
    }

    private boolean testPassphrase(PGPSecretKey key, String passphrase) throws PGPException {
        if (KeyInfo.isEncrypted(key)) {
            UnlockSecretKey.unlockSecretKey(key, Passphrase.fromPassword(passphrase));
        } else {
            if (passphrase != null) {
                return false;
            }
            UnlockSecretKey.unlockSecretKey(key, (PBESecretKeyDecryptor) null);
        }
        return true;
    }

    @Test
    @FailOnSystemExit
    public void testNoArmor() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("generate-key", "--no-armor", "Test <test@test.test>");

        byte[] outBegin = new byte[37];
        System.arraycopy(out.toByteArray(), 0, outBegin, 0, 37);
        assertFalse(Arrays.equals(outBegin, ARMOR_PRIVATE_KEY_HEADER_BYTES));
    }
}
