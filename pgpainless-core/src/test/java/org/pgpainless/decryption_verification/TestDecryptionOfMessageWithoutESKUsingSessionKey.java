// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.SessionKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestDecryptionOfMessageWithoutESKUsingSessionKey {

    private static final String encryptedMessageWithSKESK = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "jA0ECQMCc7jNEadAMZJg0j8BNtJwO2PLoRdG+VynivV7XpHp2Nw/S489vksUKct6\n" +
            "7CYTFpVTzB4IcJwmUGMmre/N1KMTznEBzy3Txa1QVBc=\n" +
            "=3M8l\n" +
            "-----END PGP MESSAGE-----";

    private static final String encryptedMessageWithoutESK = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "0j8BNtJwO2PLoRdG+VynivV7XpHp2Nw/S489vksUKct67CYTFpVTzB4IcJwmUGMm\n" +
            "re/N1KMTznEBzy3Txa1QVBc=\n" +
            "=t+pk\n" +
            "-----END PGP MESSAGE-----";

    private static final SessionKey sessionKey = new SessionKey(
            PGPSessionKey.fromAsciiRepresentation("9:26be99bc478520fbc8ab8fb84991dace4b82cfb9b00f7d05c051d69b8cea8a7f"));

    @Test
    public void decryptMessageWithSKESK() throws PGPException, IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(encryptedMessageWithSKESK.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(ConsumerOptions.get()
                        .setSessionKey(sessionKey));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
        assertEquals("Hello, World!\n", out.toString());
    }

    @Test
    public void decryptMessageWithoutSKESK() throws PGPException, IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(encryptedMessageWithoutESK.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(ConsumerOptions.get()
                        .setSessionKey(sessionKey));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
        assertEquals("Hello, World!\n", out.toString());
    }
}
