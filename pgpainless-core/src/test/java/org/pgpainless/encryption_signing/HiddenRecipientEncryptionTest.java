// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.key.SubkeyIdentifier;

/**
 * Test encryption with anonymous recipients.
 */
public class HiddenRecipientEncryptionTest {

    @Test
    public void testAnonymousRecipientRoundtrip() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPCertificate certificate = secretKeys.toCertificate();

        String msg = "Hello, World!\n";

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(ciphertextOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.get(api)
                                .addHiddenRecipient(certificate)
                ));
        encryptionStream.write(msg.getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();
        EncryptionResult result = encryptionStream.getResult();
        SubkeyIdentifier actualEncryptionKey = result.getRecipients().iterator().next();

        byte[] ciphertext = ciphertextOut.toByteArray();

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(secretKeys));

        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, plaintextOut);

        decryptionStream.close();
        MessageMetadata metadata = decryptionStream.getMetadata();

        assertEquals(msg, plaintextOut.toString());
        assertTrue(metadata.getRecipientKeyIds().contains(0L));
        assertEquals(1, metadata.getRecipientKeyIdentifiers().size());
        assertTrue(metadata.getRecipientKeyIdentifiers().get(0).isWildcard());
        assertEquals(actualEncryptionKey, metadata.getDecryptionKey());
    }
}
