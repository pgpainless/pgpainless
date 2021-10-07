// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import com.ginsberg.junit.exit.FailOnSystemExit;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.cli.PGPainlessCLI;

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
    @FailOnSystemExit
    public void dearmorSecretKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("alice@pgpainless.org", null);
        String armored = PGPainless.asciiArmor(secretKey);

        System.setIn(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("dearmor");

        assertArrayEquals(secretKey.getEncoded(), out.toByteArray());
    }


    @Test
    @FailOnSystemExit
    public void dearmorCertificate() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("alice@pgpainless.org", null);
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
        String armored = PGPainless.asciiArmor(certificate);

        System.setIn(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("dearmor");

        assertArrayEquals(certificate.getEncoded(), out.toByteArray());
    }

    @Test
    @FailOnSystemExit
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
        PGPainlessCLI.execute("dearmor");

        assertEquals("Hello, World\n", out.toString());
    }
}
