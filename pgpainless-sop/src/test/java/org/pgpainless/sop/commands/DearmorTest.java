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
package org.pgpainless.sop.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.sop.PGPainlessCLI;
import picocli.CommandLine;

public class DearmorTest {

    private PrintStream originalSout;

    @BeforeEach
    public void saveSout() {
        this.originalSout = System.out;
    }

    @AfterEach
    public void restoreSout() {
        System.setOut(originalSout);
    }

    @Test
    public void dearmorSecretKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("alice@pgpainless.org", null);
        String armored = PGPainless.asciiArmor(secretKey);

        System.setIn(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        new CommandLine(new PGPainlessCLI()).execute("dearmor");

        assertArrayEquals(secretKey.getEncoded(), out.toByteArray());
    }


    @Test
    public void dearmorCertificate() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("alice@pgpainless.org", null);
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
        String armored = PGPainless.asciiArmor(certificate);

        System.setIn(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        new CommandLine(new PGPainlessCLI()).execute("dearmor");

        assertArrayEquals(certificate.getEncoded(), out.toByteArray());
    }

    @Test
    public void dearmorMessage() {
        String armored = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.69\n" +
                "\n" +
                "SGVsbG8sIFdvcmxkCg==\n" +
                "=fkLo\n" +
                "-----END PGP MESSAGE-----";

        System.setIn(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        new CommandLine(new PGPainlessCLI()).execute("dearmor");

        assertEquals("Hello, World\n", out.toString());
    }
}
