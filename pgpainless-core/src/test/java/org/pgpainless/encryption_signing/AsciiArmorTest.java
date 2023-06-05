// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class AsciiArmorTest {

    @Test
    public void testCustomAsciiArmorComments() throws PGPException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.noEncryptionNoSigning()
                        .setAsciiArmor(true)
                        .setComment("This is a comment.\nThis is another comment."));
        encryptionStream.write("Hello, World!".getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();

        String asciiArmored = out.toString();
        assertTrue(asciiArmored.contains("Comment: This is a comment."));
        assertTrue(asciiArmored.contains("Comment: This is another comment."));
    }

    @Test
    public void testCustomAsciiArmorVersion() throws IOException, PGPException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.noEncryptionNoSigning()
                        .setAsciiArmor(true)
                        .setVersion("Custom-PGP 1.2.3"));
        encryptionStream.write("Hello, World!".getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();

        String asciiArmored = out.toString();
        assertTrue(asciiArmored.contains("Version: Custom-PGP 1.2.3"));
    }
}
