// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

public class ArmorCmdTest {

    private static PrintStream originalSout;

    @BeforeEach
    public void saveSout() {
        originalSout = System.out;
    }

    @AfterEach
    public void restoreSout() {
        System.setOut(originalSout);
    }

    @Test
    @FailOnSystemExit
    public void armorSecretKey() throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("alice@pgpainless.org");
        byte[] bytes = secretKey.getEncoded();

        System.setIn(new ByteArrayInputStream(bytes));
        ByteArrayOutputStream armorOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(armorOut));
        PGPainlessCLI.execute("armor");

        PGPSecretKeyRing armored = PGPainless.readKeyRing().secretKeyRing(armorOut.toString());
        assertArrayEquals(secretKey.getEncoded(), armored.getEncoded());
    }

    @Test
    @FailOnSystemExit
    public void armorPublicKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("alice@pgpainless.org");
        PGPPublicKeyRing publicKey = PGPainless.extractCertificate(secretKey);
        byte[] bytes = publicKey.getEncoded();

        System.setIn(new ByteArrayInputStream(bytes));
        ByteArrayOutputStream armorOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(armorOut));
        PGPainlessCLI.execute("armor");

        PGPPublicKeyRing armored = PGPainless.readKeyRing().publicKeyRing(armorOut.toString());
        assertArrayEquals(publicKey.getEncoded(), armored.getEncoded());
    }

    @Test
    @FailOnSystemExit
    public void armorMessage() {
        String message = "Hello, World!\n";

        System.setIn(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream armorOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(armorOut));
        PGPainlessCLI.execute("armor");

        String armored = armorOut.toString();

        assertTrue(armored.startsWith("-----BEGIN PGP MESSAGE-----\n"));
        assertTrue(armored.contains("SGVsbG8sIFdvcmxkIQo="));
    }

}
