// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.symmetric_encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class MultiPassphraseSymmetricEncryptionTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void encryptDecryptWithMultiplePassphrases() throws IOException, PGPException {
        String message = "Here we test if during decryption of a message that was encrypted with two passphrases, " +
                "the decryptor finds the session key encrypted for the right passphrase.";
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        EncryptionStream encryptor = PGPainless.getInstance().generateMessage()
                .onOutputStream(ciphertextOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.encryptCommunications()
                        .addMessagePassphrase(Passphrase.fromPassword("p1"))
                        .addMessagePassphrase(Passphrase.fromPassword("p2"))
                ).setAsciiArmor(false));

        Streams.pipeAll(plaintextIn, encryptor);
        encryptor.close();

        byte[] ciphertext = ciphertextOut.toByteArray();

        // decrypting the p1 package with p2 first will not work. Test if it is handled correctly.
        for (Passphrase passphrase : new Passphrase[] {Passphrase.fromPassword("p2"), Passphrase.fromPassword("p1")}) {
            DecryptionStream decryptor = PGPainless.getInstance().processMessage()
                    .onInputStream(new ByteArrayInputStream(ciphertext))
                    .withOptions(ConsumerOptions.get()
                    .addMessagePassphrase(passphrase));

            ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();

            Streams.pipeAll(decryptor, plaintextOut);

            decryptor.close();
        }
    }
}
