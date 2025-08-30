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

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;

public class ExtractCertCmdTest extends CLITest {

    private final PGPainless api = PGPainless.getInstance();

    public ExtractCertCmdTest() {
        super(LoggerFactory.getLogger(ExtractCertCmdTest.class));
    }

    @Test
    public void testExtractCert()
            throws IOException {
        OpenPGPKey key = api.generateKey()
                .simpleEcKeyRing("Juliet Capulet <juliet@capulet.lit>");

        pipeBytesToStdin(key.getEncoded());
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("extract-cert", "--armor"));

        assertTrue(out.toString().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));

        OpenPGPCertificate certificate = api.readKey().parseCertificate(out.toByteArray());
        KeyRingInfo info = api.inspect(certificate);
        assertFalse(info.isSecretKey());
        assertTrue(info.isUserIdValid("Juliet Capulet <juliet@capulet.lit>"));
    }

    @Test
    public void testExtractCertFromCertFails() throws IOException {
        // Generate key
        File keyFile = pipeStdoutToFile("key.asc");
        assertSuccess(executeCommand("generate-key", "Alice <alice@pgpainless.org>"));

        // extract cert from key (success)
        pipeFileToStdin(keyFile);
        File certFile = pipeStdoutToFile("cert.asc");
        assertSuccess(executeCommand("extract-cert"));

        // extract cert from cert (fail)
        pipeFileToStdin(certFile);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("extract-cert");

        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void extractCertFromGarbageFails() throws IOException {
        pipeStringToStdin("This is a bunch of garbage!");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("extract-cert");

        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testExtractCertUnarmored() throws IOException {
        // Generate key
        File keyFile = pipeStdoutToFile("key.asc");
        assertSuccess(executeCommand("generate-key", "Alice <alice@pgpainless.org>"));

        // extract cert from key (success)
        pipeFileToStdin(keyFile);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("extract-cert", "--no-armor"));

        assertFalse(out.toString().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));

        pipeBytesToStdin(out.toByteArray());
        ByteArrayOutputStream armored = pipeStdoutToStream();
        assertSuccess(executeCommand("armor"));

        assertTrue(armored.toString().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
    }

}
