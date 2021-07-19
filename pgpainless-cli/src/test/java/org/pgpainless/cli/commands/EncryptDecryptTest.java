/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

public class EncryptDecryptTest {

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
        File julietKeyFile = new File(tempDir, "juliet.key");
        assertTrue(julietKeyFile.createNewFile());

        File julietCertFile = new File(tempDir, "juliet.asc");
        assertTrue(julietCertFile.createNewFile());

        File romeoKeyFile = new File(tempDir, "romeo.key");
        assertTrue(romeoKeyFile.createNewFile());

        File romeoCertFile = new File(tempDir, "romeo.asc");
        assertTrue(romeoCertFile.createNewFile());

        File msgAscFile = new File(tempDir, "msg.asc");
        assertTrue(msgAscFile.createNewFile());

        OutputStream julietKeyOut = new FileOutputStream(julietKeyFile);
        System.setOut(new PrintStream(julietKeyOut));
        PGPainlessCLI.execute("generate-key", "Juliet Capulet <juliet@capulet.lit>");
        julietKeyOut.close();

        FileInputStream julietKeyIn = new FileInputStream(julietKeyFile);
        System.setIn(julietKeyIn);
        OutputStream julietCertOut = new FileOutputStream(julietCertFile);
        System.setOut(new PrintStream(julietCertOut));
        PGPainlessCLI.execute("extract-cert");
        julietKeyIn.close();
        julietCertOut.close();

        OutputStream romeoKeyOut = new FileOutputStream(romeoKeyFile);
        System.setOut(new PrintStream(romeoKeyOut));
        PGPainlessCLI.execute("generate-key", "Romeo Montague <romeo@montague.lit>");
        romeoKeyOut.close();

        FileInputStream romeoKeyIn = new FileInputStream(romeoKeyFile);
        System.setIn(romeoKeyIn);
        OutputStream romeoCertOut = new FileOutputStream(romeoCertFile);
        System.setOut(new PrintStream(romeoCertOut));
        PGPainlessCLI.execute("extract-cert");
        romeoKeyIn.close();
        romeoCertOut.close();

        String msg = "Hello World!\n";
        ByteArrayInputStream msgIn = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8));
        System.setIn(msgIn);
        OutputStream msgAscOut = new FileOutputStream(msgAscFile);
        System.setOut(new PrintStream(msgAscOut));
        PGPainlessCLI.execute("encrypt",
                "--sign-with", romeoKeyFile.getAbsolutePath(),
                julietCertFile.getAbsolutePath());
        msgAscOut.close();

        File verifyFile = new File(tempDir, "verify.txt");

        FileInputStream msgAscIn = new FileInputStream(msgAscFile);
        System.setIn(msgAscIn);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream pOut = new PrintStream(out);
        System.setOut(pOut);
        PGPainlessCLI.execute("decrypt",
                "--verify-out", verifyFile.getAbsolutePath(),
                "--verify-with", romeoCertFile.getAbsolutePath(),
                julietKeyFile.getAbsolutePath());
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
