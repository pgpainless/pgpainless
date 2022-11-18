// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;

public class GenerateKeyCmdTest extends CLITest {

    public GenerateKeyCmdTest() {
        super(LoggerFactory.getLogger(GenerateKeyCmdTest.class));
    }

    @Test
    public void testGenerateKey() throws IOException {
        File keyFile = pipeStdoutToFile("key.asc");
        assertSuccess(executeCommand("generate-key", "Alice <alice@pgpainless.org>"));

        String key = readStringFromFile(keyFile);
        assertTrue(key.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"));
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(key);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isFullyDecrypted());
        assertEquals(Collections.singletonList("Alice <alice@pgpainless.org>"), info.getUserIds());
    }

    @Test
    public void testGenerateBinaryKey() throws IOException {
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("generate-key", "--no-armor",
                "Alice <alice@pgpainless.org>"));

        byte[] key = out.toByteArray();
        String firstHexOctet = Hex.toHexString(key, 0, 1);
        assertTrue(firstHexOctet.equals("c5") || firstHexOctet.equals("94"));
    }

    @Test
    public void testGenerateKeyWithMultipleUserIds() throws IOException {
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("generate-key",
                "Alice <alice@pgpainless.org>", "Alice <alice@openpgp.org>"));

        String key = out.toString();
        assertTrue(key.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"));
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(key);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isFullyDecrypted());
        assertEquals(Arrays.asList("Alice <alice@pgpainless.org>", "Alice <alice@openpgp.org>"), info.getUserIds());
    }

    @Test
    public void testPasswordProtectedKey() throws IOException, PGPException {
        File passwordFile = writeFile("password", "sw0rdf1sh");
        passwordFile.deleteOnExit();
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("generate-key",
                "--with-key-password", passwordFile.getAbsolutePath(), "Alice <alice@pgpainless.org>"));

        String key = out.toString();
        assertTrue(key.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"));
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(key);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isFullyEncrypted());

        assertNotNull(UnlockSecretKey
                .unlockSecretKey(secretKeys.getSecretKey(), Passphrase.fromPassword("sw0rdf1sh")));
    }

    @Test
    public void testGeneratePasswordProtectedKey_missingPasswordFile() throws IOException {
        int exit = executeCommand("generate-key",
                "--with-key-password", "nonexistent", "Alice <alice@pgpainless.org>");

        assertEquals(SOPGPException.MissingInput.EXIT_CODE, exit,
                "Expected MISSING_INPUT (" + SOPGPException.MissingInput.EXIT_CODE + ")");
    }
}
