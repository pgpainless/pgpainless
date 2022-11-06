// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import com.ginsberg.junit.exit.FailOnSystemExit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.cli.PGPainlessCLI;
import org.pgpainless.cli.TestUtils;

public class RoundTripInlineSignVerifyCmdTest {
    private static File tempDir;
    private static PrintStream originalSout;

    @BeforeAll
    public static void prepare() throws IOException {
        tempDir = TestUtils.createTempDirectory();
    }

    @Test
    @FailOnSystemExit
    public void encryptAndDecryptAMessage() throws IOException {
        originalSout = System.out;
        File sigmundKeyFile = new File(tempDir, "sigmund.key");
        assertTrue(sigmundKeyFile.createNewFile());

        File sigmundCertFile = new File(tempDir, "sigmund.cert");
        assertTrue(sigmundCertFile.createNewFile());

        File msgFile = new File(tempDir, "signed.asc");
        assertTrue(msgFile.createNewFile());

        File passwordFile = new File(tempDir, "password");
        assertTrue(passwordFile.createNewFile());

        // write password file
        FileOutputStream passwordOut = new FileOutputStream(passwordFile);
        passwordOut.write("sw0rdf1sh".getBytes(StandardCharsets.UTF_8));
        passwordOut.close();

        // generate key
        OutputStream sigmundKeyOut = new FileOutputStream(sigmundKeyFile);
        System.setOut(new PrintStream(sigmundKeyOut));
        PGPainlessCLI.execute("generate-key",
                "--with-key-password=" + passwordFile.getAbsolutePath(),
                "Sigmund Freud <sigmund@pgpainless.org>");
        sigmundKeyOut.close();

        // extract cert
        FileInputStream sigmundKeyIn = new FileInputStream(sigmundKeyFile);
        System.setIn(sigmundKeyIn);
        OutputStream sigmundCertOut = new FileOutputStream(sigmundCertFile);
        System.setOut(new PrintStream(sigmundCertOut));
        PGPainlessCLI.execute("extract-cert");
        sigmundKeyIn.close();
        sigmundCertOut.close();

        // sign message
        String msg = "Hello World!\n";
        ByteArrayInputStream msgIn = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8));
        System.setIn(msgIn);
        OutputStream msgAscOut = new FileOutputStream(msgFile);
        System.setOut(new PrintStream(msgAscOut));
        PGPainlessCLI.execute("inline-sign",
                "--with-key-password=" + passwordFile.getAbsolutePath(),
                sigmundKeyFile.getAbsolutePath());
        msgAscOut.close();

        File verifyFile = new File(tempDir, "verify.txt");

        FileInputStream msgAscIn = new FileInputStream(msgFile);
        System.setIn(msgAscIn);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream pOut = new PrintStream(out);
        System.setOut(pOut);
        PGPainlessCLI.execute("inline-verify",
                "--verifications-out", verifyFile.getAbsolutePath(),
                sigmundCertFile.getAbsolutePath());
        msgAscIn.close();

        assertEquals(msg, out.toString());
    }

    @AfterAll
    public static void after() {
        System.setOut(originalSout);
        // CHECKSTYLE:OFF
        System.out.println(tempDir.getAbsolutePath());
        // CHECKSTYLE:ON
    }
}
