// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

public class RoundTripInlineSignVerifyCmdTest extends CLITest {

    public RoundTripInlineSignVerifyCmdTest() {
        super(LoggerFactory.getLogger(RoundTripInlineSignVerifyCmdTest.class));
    }

    @Test
    public void encryptAndDecryptAMessage() throws IOException {
        // write password file
        File password = writeFile("password", "sw0rdf1sh");

        // generate key
        File sigmundKey = pipeStdoutToFile("sigmund.key");
        assertSuccess(executeCommand("generate-key", "--with-key-password=" + password.getAbsolutePath(),
                "Sigmund Freud <sigmund@pgpainless.org>"));

        // extract cert
        File sigmundCert = pipeStdoutToFile("sigmund.cert");
        pipeFileToStdin(sigmundKey);
        assertSuccess(executeCommand("extract-cert"));

        // sign message
        pipeBytesToStdin("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        File signedMsg = pipeStdoutToFile("signed.asc");
        assertSuccess(executeCommand("inline-sign", "--with-key-password=" + password.getAbsolutePath(),
                sigmundKey.getAbsolutePath()));

        // verify message
        File verifyFile = nonExistentFile("verify.txt");
        pipeFileToStdin(signedMsg);
        assertSuccess(executeCommand("inline-verify", "--verifications-out", verifyFile.getAbsolutePath(),
                sigmundCert.getAbsolutePath()));

        String verifications = readStringFromFile(verifyFile);
        assertFalse(verifications.trim().isEmpty());
    }
}
