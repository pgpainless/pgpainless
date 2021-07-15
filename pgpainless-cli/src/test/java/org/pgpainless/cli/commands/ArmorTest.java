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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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

public class ArmorTest {

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
                .modernKeyRing("alice@pgpainless.org", null);
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
                .modernKeyRing("alice@pgpainless.org", null);
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

    @Test
    @FailOnSystemExit
    public void doesNotNestArmorByDefault() {
        String armored = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.69\n" +
                "\n" +
                "SGVsbG8sIFdvcmxkCg==\n" +
                "=fkLo\n" +
                "-----END PGP MESSAGE-----";

        System.setIn(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("armor");

        assertEquals(armored, out.toString());
    }

    @Test
    @FailOnSystemExit
    public void testAllowNested() {
        String armored = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.69\n" +
                "\n" +
                "SGVsbG8sIFdvcmxkCg==\n" +
                "=fkLo\n" +
                "-----END PGP MESSAGE-----";

        System.setIn(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("armor", "--allow-nested");

        assertNotEquals(armored, out.toString());
        assertTrue(out.toString().contains(
                "LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tClZlcnNpb246IEJDUEcgdjEuNjkK\n" +
                "ClNHVnNiRzhzSUZkdmNteGtDZz09Cj1ma0xvCi0tLS0tRU5EIFBHUCBNRVNTQUdF\n" +
                "LS0tLS0="));
    }
}
